#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let cth = clickhouse_driver_cth::city_hash_64(data);
    let our = ch_cityhash102::cityhash64(data);
    assert_eq!(cth, our);
});
