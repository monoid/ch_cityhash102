#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let cth = clickhouse_driver_cth::city_hash_128(data);
    let our = ch_cityhash102::cityhash128(data);
    assert_eq!((cth.0, cth.1), (our.first, our.second));
});
