# Clickhouse CityHash

`ch_cityhash102` is a native no_std Rust implementation of ClickHouse's
CityHash version.  ClickHouse uses fixed old version of the
CityHash algorithm (1.0.2, as per
<https://github.com/ClickHouse/ClickHouse/issues/8354>).

Two versions are implemented: `cityhash64` used in ClickHouse's query
language, and `cityhash128` used in the ClickHouse protocol.
