/* This module contains tests that use std.  We cannot include it into
 * lib.rs as it is no_std.
 */

use ch_cityhash102::{cityhash128, cityhash64};
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
