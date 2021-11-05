/* This module contains tests that use std.  We cannot include it into
 * lib.rs as it is no_std.
 */

use ch_cityhash102::{cityhash128, cityhash64};
#[cfg(feature = "test_with_clickhouse_driver")]
use clickhouse_driver_cth;
use fake::Fake;

#[test]
fn test_64_unaligned() {
    let aligned = (2..40).fake::<String>();
    let unaligned = format!("u{}", aligned);
    let aligned = aligned.as_bytes();
    let unaligned = unaligned.as_bytes();

    for start in 0..aligned.len() - 1 {
        for end in start..aligned.len() {
            assert_eq!(
                cityhash64(&aligned[start..end]),
                cityhash64(&unaligned[(start + 1)..(end + 1)]),
                "Failed unaligned at [{}..{}]",
                start,
                end,
            );
        }
    }
}

#[test]
fn test_128_unaligned() {
    // Strings buffers are allocated and thus are usually aligned.
    let aligned = (2..40).fake::<String>();
    // Build a string with extra char so that it is aligned differently.
    let unaligned = format!("u{}", aligned);
    let aligned = aligned.as_bytes();
    let unaligned = unaligned.as_bytes();

    for start in 0..aligned.len() - 1 {
        for end in start..aligned.len() {
            assert_eq!(
                cityhash128(&aligned[start..end]),
                cityhash128(&unaligned[(start + 1)..(end + 1)]),
                "Failed unaligned at [{}..{}]",
                start,
                end,
            );
        }
    }
}

/* Test against clickhouse_driver cityhash bindings. */

#[cfg(feature = "test_with_clickhouse_driver")]
#[quickcheck_macros::quickcheck]
fn qc_64_against_cxx(data: Vec<u8>) -> bool {
    cityhash64(data.as_ref()) == clickhouse_driver_cth::city_hash_64(data.as_ref())
}

#[cfg(feature = "test_with_clickhouse_driver")]
#[quickcheck_macros::quickcheck]
fn qc_128_against_cxx(data: Vec<u8>) -> bool {
    let our = cityhash128(data.as_ref());
    let theirs = clickhouse_driver_cth::city_hash_128(data.as_ref());
    (our.first, our.second) == (theirs.0, theirs.1)
}
