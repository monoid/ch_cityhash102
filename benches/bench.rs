use ch_cityhash102::{cityhash128, cityhash64};

#[cfg(feature="bench_with_clickhouse_driver")]
use clickhouse_driver_cth;
#[cfg(feature="bench_with_clickhouse_driver")]
use clickhouse_driver_cthrs;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

criterion_group!(benches, bench_compare);
criterion_main!(benches);

fn bench_compare(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashing");
    let data = &[
        &b"test"[..],
        &b"me"[..],
        &b"one"[..],
        &b"more time, please"[..],
        // CityHash is intended for short strings, so it may worth splitting it into multiple ones;
        // total length should be more than cache size.
        //
        // One should use quote from some famous text, perhaps.  Apple
        // M1 processor has 256K cache size; Intel's one seem to have 1-2M.  "War an
        // peace"'s orignal text is 300K.
        &b"very long string that is intended to not fit into a caches line, but I'm not sure I will be able to achive it; I will try as much as I can; but it is not guaranteed; but I shouldn't stop writing this text as long as possible; I requires some efforts, but good benchmark worth it!"[..],
    ][..];

    group.bench_with_input(
        BenchmarkId::new("cityhash64", "our-short"),
        &data[..4],
        |b, i| {
            b.iter(|| {
                i.iter().cloned().for_each(|v| {
                    black_box(cityhash64(v));
                })
            })
        },
    );

    #[cfg(feature="bench_with_clickhouse_driver")]
    group.bench_with_input(
        BenchmarkId::new("cityhash64", "cth-short"),
        &data[..4],
        |b, i| {
            b.iter(|| {
                i.iter().cloned().for_each(|v| {
                    black_box(clickhouse_driver_cth::city_hash_64(v));
                })
            })
        },
    );

    group.bench_with_input(BenchmarkId::new("cityhash64", "our-long"), data, |b, i| {
        b.iter(|| {
            i.iter().cloned().for_each(|v| {
                black_box(cityhash64(v));
            })
        })
    });

    #[cfg(feature="bench_with_clickhouse_driver")]
    group.bench_with_input(BenchmarkId::new("cityhash64", "cth-long"), data, |b, i| {
        b.iter(|| {
            i.iter().cloned().for_each(|v| {
                black_box(clickhouse_driver_cth::city_hash_64(v));
            })
        })
    });

    group.bench_with_input(
        BenchmarkId::new("cityhash128", "our-short"),
        &data[..4],
        |b, i| {
            b.iter(|| {
                i.iter().cloned().for_each(|v| {
                    black_box(cityhash128(v));
                })
            })
        },
    );

    #[cfg(feature="bench_with_clickhouse_driver")]
    group.bench_with_input(
        BenchmarkId::new("cityhash128", "cth-short"),
        &data[..4],
        |b, i| {
            b.iter(|| {
                i.iter().cloned().for_each(|v| {
                    black_box(clickhouse_driver_cth::city_hash_128(v));
                })
            })
        },
    );

    #[cfg(feature="bench_with_clickhouse_driver")]
    group.bench_with_input(
        BenchmarkId::new("cityhash128", "cthrs-short"),
        &data[..4],
        |b, i| {
            b.iter(|| {
                i.iter().cloned().for_each(|v| {
                    black_box(clickhouse_driver_cthrs::city_hash_128(v));
                })
            })
        },
    );

    group.bench_with_input(BenchmarkId::new("cityhash128", "our-long"), data, |b, i| {
        b.iter(|| {
            i.iter().cloned().for_each(|v| {
                black_box(cityhash128(v));
            })
        })
    });

    #[cfg(feature="bench_with_clickhouse_driver")]
    group.bench_with_input(BenchmarkId::new("cityhash128", "cth-long"), data, |b, i| {
        b.iter(|| {
            i.iter().cloned().for_each(|v| {
                black_box(clickhouse_driver_cth::city_hash_128(v));
            })
        })
    });

    #[cfg(feature="bench_with_clickhouse_driver")]
    group.bench_with_input(BenchmarkId::new("cityhash128", "cthrs-long"), data, |b, i| {
        b.iter(|| {
            i.iter().cloned().for_each(|v| {
                black_box(clickhouse_driver_cthrs::city_hash_128(v));
            })
        })
    });
}
