use std::io::{self, BufWriter, Write};

use bitpacking::{BitPacker, BitPacker4x};
use ownedbytes::OwnedBytes;
use rice_coder::{estimate_optimal_k, RiceCoder};
use tantivy_common::{BinarySerializable, VInt};

// Define a struct for docid-value pairs
#[derive(Debug, Clone)]
pub struct DocIdValue<T> {
    pub docid: u32,
    pub value: T, // Numeric value as u64
}

pub fn write_docids_from_iter<I, W>(iter: I, mut writer: W) -> io::Result<()>
where
    I: IntoIterator<Item = u32>,
    W: Write,
{
    let docids: Vec<u32> = iter.into_iter().collect();

    let bitpacker = BitPacker4x::new();

    // Write docids in block of 128
    let mut out = vec![0; BitPacker4x::BLOCK_LEN * 4];
    for chunk in docids.chunks(128) {
        writer.write_all(&[chunk.len() as u8])?;
        if chunk.len() < 128 {
            let mut docid_writer = DocidListWriterVInt::new(&mut writer);
            for docid in chunk {
                docid_writer.write_docid(*docid)?;
            }
            docid_writer.finish()?;
        } else {
            let num_bits = bitpacker.num_bits_sorted(chunk[0], chunk);
            writer.write_all(&[num_bits])?;
            // If don't manually write the first doc, the compression gets bad
            writer.write_all(&chunk[0].to_be_bytes())?;
            let written_size = bitpacker.compress_sorted(chunk[0], chunk, &mut out, num_bits);
            writer.write_all(&out[..written_size])?;
        }
    }
    Ok(())
}

pub fn get_delta_docids(docids: &mut [u32]) {
    let mut last_docid = 0;
    for docid in docids.iter_mut() {
        let delta = *docid - last_docid;
        last_docid = *docid;
        *docid = delta;
    }
}

pub fn write_rice_code_docids_from_iter<I, W>(iter: I, mut writer: W, k: u8) -> io::Result<()>
where
    I: IntoIterator<Item = u32>,
    W: Write,
{
    let mut docids: Vec<u32> = iter.into_iter().collect();

    // Write docids in block of 128
    let mut output = Vec::new();
    for chunk in docids.chunks_mut(128) {
        get_delta_docids(chunk);
        let (first, chunk) = chunk.split_at(1);
        //let k = estimate_optimal_k(chunk, 100.0);
        writer.write_all(&[k])?;
        writer.write_all(&first[0].to_be_bytes())?;
        let mut coder = RiceCoder::new(k);
        coder.encode_vals(chunk, &mut output);
        writer.write_all(&output)?;
        output.clear();
    }
    Ok(())
}

pub fn write_rice_code_docids_from_iter_detect_k<I, W>(
    iter: I,
    mut writer: W,
    percentile: usize,
) -> io::Result<()>
where
    I: IntoIterator<Item = u32>,
    W: Write,
{
    let mut docids: Vec<u32> = iter.into_iter().collect();

    // Write docids in block of 128
    let mut output = vec![0; 128];
    for chunk in docids.chunks_mut(128) {
        get_delta_docids(chunk);
        let k = estimate_optimal_k(chunk, percentile);
        let (first, chunk) = chunk.split_at(1);
        writer.write_all(&[k])?;
        writer.write_all(&first[0].to_be_bytes())?;
        let mut coder = RiceCoder::new(k);
        coder.encode_vals(chunk, &mut output);
        writer.write_all(&output)?;
        output.clear();
    }
    Ok(())
}
/// Decodes based on write_rice_code_docids_from_iter_detect_k
pub fn decode_rice_encoded_docids(data: &[u8]) -> Vec<u32> {
    let mut docids = Vec::new();
    let mut input = data;
    while !input.is_empty() {
        let k = input[0];
        let coder = RiceCoder::new(k);
        let mut prev = u32::from_be_bytes(input[1..5].try_into().unwrap());
        docids.push(prev);
        let mut chunk = Vec::new();
        input = &input[5..];
        let num_bytes_read = coder.decode_into(input, &mut chunk);
        for docid in chunk {
            prev = docid.wrapping_add(prev);
            docids.push(prev);
        }
        input = &input[num_bytes_read..];
    }
    docids
}

pub fn write_vint_docids_from_iter<I, W>(iter: I, mut writer: W) -> io::Result<()>
where
    I: IntoIterator<Item = u32>,
    W: Write,
{
    let mut docid_writer = DocidListWriterVInt::new(&mut writer);
    for docid in iter {
        docid_writer.write_docid(docid)?;
    }
    docid_writer.finish()?;
    Ok(())
}

pub fn write_roaring_docids_from_iter<I, W>(iter: I, writer: W) -> io::Result<()>
where
    I: IntoIterator<Item = u32>,
    W: Write,
{
    use roaring::RoaringBitmap;

    let rb1: RoaringBitmap = iter.into_iter().collect();
    rb1.serialize_into(writer).unwrap();
    Ok(())
}

// DocidList writer
pub struct DocidListWriterVInt<W: Write> {
    writer: BufWriter<W>,
    last_written: u32,
}

impl<W: Write> DocidListWriterVInt<W> {
    pub fn new(writer: W) -> Self {
        DocidListWriterVInt {
            writer: BufWriter::new(writer),
            last_written: 0,
        }
    }

    pub fn write_docid(&mut self, docid: u32) -> io::Result<()> {
        let delta = docid.wrapping_sub(self.last_written);
        self.last_written = docid;
        let vint = VInt(delta as u64);
        let mut buffer = Vec::new();
        vint.serialize_into_vec(&mut buffer);
        self.writer.write_all(&buffer)?;
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

pub struct DocidListReaderMixed {
    bytes: OwnedBytes,
    current_block: Vec<u32>,
    block_pos: usize,
}

impl DocidListReaderMixed {
    pub fn new(bytes: OwnedBytes) -> Self {
        Self {
            bytes,
            current_block: Vec::new(),
            block_pos: 0,
        }
    }

    fn decode_next_block(&mut self) -> Option<()> {
        if self.bytes.is_empty() {
            return None;
        }

        let num_docs = self.bytes[0];
        if num_docs < 128 {
            // Last block with fewer than 128 documents, using VInt
            self.bytes.advance(1);
            let reader = DocidListReaderVInt::new(self.bytes.clone());
            self.current_block = reader.collect();
            self.bytes.advance(self.bytes.len()); // finish
        } else {
            // Block with bitpacking
            let num_bits = self.bytes[1];
            let first_doc: u32 = u32::from_be_bytes(self.bytes[2..6].try_into().unwrap());
            let mut docids = vec![0; num_docs as usize];
            let bitpacker = BitPacker4x::new();
            let num_bytes_decompressed =
                bitpacker.decompress_sorted(first_doc, &self.bytes[6..], &mut docids, num_bits);
            self.current_block = docids;
            self.bytes.advance(num_bytes_decompressed + 6); // Advance after reading
        }

        self.block_pos = 0; // Reset block position for new block
        Some(())
    }
}

impl Iterator for DocidListReaderMixed {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        if self.block_pos >= self.current_block.len() {
            // If we are out of docids in the current block, try decoding the next block
            self.decode_next_block()?;
        }
        let docid = self.current_block[self.block_pos];
        self.block_pos += 1;
        Some(docid)
    }
}

// DocidList reader, now using OwnedBytes and implementing Iterator
pub struct DocidListReaderVInt {
    bytes: OwnedBytes,
    last_read: u32,
}

impl DocidListReaderVInt {
    pub fn new(bytes: OwnedBytes) -> Self {
        DocidListReaderVInt {
            bytes,
            last_read: 0,
        }
    }
}

// Implement Iterator for DocidListReader
impl Iterator for DocidListReaderVInt {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        // Check if we have any bytes left in the buffer
        if self.bytes.is_empty() {
            return None; // No more data to read
        }
        let vint = VInt::deserialize(&mut self.bytes).ok()?;
        let delta = vint.val() as u32;
        self.last_read = self.last_read.wrapping_add(delta);
        Some(self.last_read)
    }
}

// Test function
#[cfg(test)]
mod tests {
    use crate::DocIdValue;

    use super::*;
    use ownedbytes::OwnedBytes;
    use rand::prelude::Distribution;

    #[test]
    fn test_docid_list_iterator_short() {
        test_docid_list(&[10, 20, 30, 50, 80]);
    }

    #[test]
    fn test_docid_list_iterator_len128() {
        let docids: Vec<u32> = (0..128).collect();
        test_docid_list(&docids);
    }

    #[test]
    fn test_docid_list_iterator_len150() {
        let docids: Vec<u32> = (0..150).collect();
        test_docid_list(&docids);
    }
    #[test]
    fn test_docid_list_multi_blocks() {
        let docids: Vec<u32> = (0..1000).collect();
        test_docid_list(&docids);
    }

    fn test_docid_list(docids: &[u32]) {
        let mut buffer = Vec::new();
        write_docids_from_iter(docids.iter().cloned(), &mut buffer).unwrap();
        // Convert buffer to OwnedBytes and read docids using iterator
        let owned_bytes = OwnedBytes::new(buffer);
        let reader = DocidListReaderMixed::new(owned_bytes);
        let read_docids: Vec<u32> = reader.collect();

        // Ensure the written docids match the read docids
        assert_eq!(docids, read_docids);

        let mut buffer = Vec::new();
        write_rice_code_docids_from_iter_detect_k(docids.iter().cloned(), &mut buffer, 80).unwrap();
        let decoded = decode_rice_encoded_docids(&buffer);
        assert_eq!(docids, decoded);
    }

    #[test]
    fn test_size() {
        let docids: Vec<u32> = (0..1000).collect();

        let mut out = Vec::new();
        write_vint_docids_from_iter(docids.iter().cloned(), &mut out).unwrap();
        assert_eq!(out.len(), 1000);
        let mut out = Vec::new();
        write_docids_from_iter(docids.iter().cloned(), &mut out).unwrap();
        assert_eq!(out.len(), 260);

        let mut rng = rand::thread_rng();
        let zipf = zipf::ZipfDistribution::new(20, 1.5).unwrap();
        //dbg!(zipf.sample(&mut rng) as u64);

        let mut data: Vec<(&str, Vec<DocIdValue<u64>>)> = vec![
            (
                "sequential with gaps",
                (0..5_000_000)
                    .filter(|&docid| docid % 10 != 0) // every 10th value is missing
                    .map(|docid| DocIdValue {
                        docid,
                        value: docid as u64,
                    })
                    .collect(),
            ),
            (
                "zipf log levels",
                (0..5_000_000)
                    .map(|docid| DocIdValue {
                        docid,
                        value: zipf.sample(&mut rng) as u64,
                    })
                    .collect(),
            ),
            (
                "sorted values",
                (0..5_000_000)
                    .map(|docid| DocIdValue {
                        docid,
                        value: docid as u64,
                    })
                    .collect(),
            ),
            (
                "many random unique values",
                (0..5_000_000)
                    .map(|docid| DocIdValue {
                        docid,
                        value: rand::random::<u64>(),
                    })
                    .collect(),
            ),
        ];
        for data in data.iter_mut() {
            data.1.sort_unstable_by_key(|x| x.value);
        }
    }
}
