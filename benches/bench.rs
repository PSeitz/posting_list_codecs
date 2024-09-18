use binggan::{BenchRunner, PeakMemAlloc, INSTRUMENTED_SYSTEM};
use posting_list_codecs::*;
use rand::prelude::Distribution;

#[global_allocator]
pub static GLOBAL: &PeakMemAlloc<std::alloc::System> = &INSTRUMENTED_SYSTEM;

fn bench_group() {
    // Tuples of name and data for the inputs
    let mut rng = rand::thread_rng();
    let zipf = zipf::ZipfDistribution::new(20, 1.5).unwrap();
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
            "random order",
            (0..5_000_000)
                .map(|docid| DocIdValue {
                    docid,
                    value: rand::random::<u64>(),
                })
                .collect(),
        ),
    ];
    for data in data.iter_mut() {
        data.1.sort_by_key(|x| x.value);
    }

    let mut runner: BenchRunner = BenchRunner::new();
    runner.set_alloc(GLOBAL); // Set the peak mem allocator. This will enable peak memory reporting.
    runner.set_name("docid list encoding");

    runner.config().set_cache_trasher(true);

    for num_docs in [1000, 10_000] {
        // Compare docid lists, by sampling the first 1000 docs
        for (input_name, data) in data.iter() {
            let mut data: Vec<u32> = data[..num_docs].iter().map(|el| el.docid).collect();
            // This is to simulate the docids for one block, e.g. one term or one leaf in a bkd-tree
            // We can sort the docids in those cases.
            data.sort();
            let mut group = runner.new_group();
            group.set_name(format!("{input_name} {num_docs} docs"));
            group.set_input_size(data.len() * 4);
            for k in 1..7 {
                group.register_with_input(format!("rice code k {}", k), &data, move |data| {
                    let mut out = Vec::new();
                    write_rice_code_docids_from_iter(data.iter().cloned(), &mut out, k).unwrap();
                    Some(out.len() as u64)
                });
            }
            group.register_with_input("rice code detect k 75.0 percentile", &data, move |data| {
                let mut out = Vec::new();
                write_rice_code_docids_from_iter_detect_k(data.iter().cloned(), &mut out, 75)
                    .unwrap();
                Some(out.len() as u64)
            });

            group.register_with_input("vint code", &data, move |data| {
                let mut out = Vec::new();
                write_vint_docids_from_iter(data.iter().cloned(), &mut out).unwrap();
                Some(out.len() as u64)
            });
            group.register_with_input("vint + bitpack 4x code", &data, move |data| {
                let mut out = Vec::new();
                write_docids_from_iter(data.iter().cloned(), &mut out).unwrap();
                Some(out.len() as u64)
            });
            group.register_with_input("roaring bitmaps", &data, move |data| {
                let mut out = Vec::new();
                write_roaring_docids_from_iter(data.iter().cloned(), &mut out).unwrap();
                Some(out.len() as u64)
            });

            group.run();
        }
    }
}

fn main() {
    bench_group();
}
