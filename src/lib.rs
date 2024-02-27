/*
Copyright (c) 2021 Ivan Boldyrev
Copyright (c) 2011 Google, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
 */

/*!
# Features

This crate has only single feature used exclusively for testing/benchmarking.

* **test_with_clickhouse_driver** -
  Test and benchmark against
  <https://github.com/ddulesov/clickhouse_driver/>, both native and
  C++ implementations.
*/
#![no_std]
#![allow(clippy::many_single_char_names)]
use core::num::Wrapping;

type W64 = Wrapping<u64>;
type W32 = Wrapping<u32>;

/** C++ CityHash-compatible `uint128` type.

While Rust has native `u128` type, we've decided to use compatible type
of two `u64` fields.  The `From<u128>` and `Into<u128>` are implemented
for this type for your convenience.
*/
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U128 {
    pub first: u64,
    pub second: u64,
}

impl U128 {
    #[inline]
    pub const fn new(first: u64, second: u64) -> Self {
        Self { first, second }
    }

    /** Lower half of the `U128`. */
    #[inline]
    pub const fn lo(&self) -> u64 {
        self.first
    }

    /** Higher half of the `U128`. */
    #[inline]
    pub const fn hi(&self) -> u64 {
        self.second
    }

    const fn from_w64(first: W64, second: W64) -> Self {
        Self {
            first: first.0,
            second: second.0,
        }
    }
}

impl From<u128> for U128 {
    #[inline]
    fn from(source: u128) -> Self {
        Self {
            first: source as u64,
            second: (source >> 64) as u64,
        }
    }
}

impl From<U128> for u128 {
    #[inline]
    fn from(val: U128) -> Self {
        (val.first as u128) | ((val.second as u128) << 64)
    }
}

const fn w64(v: u64) -> W64 {
    Wrapping(v)
}

const fn w32(v: u32) -> W32 {
    Wrapping(v)
}

// Some primes between 2^63 and 2^64 for various uses.
const K0: W64 = w64(0xc3a5c85c97cb3127u64);
const K1: W64 = w64(0xb492b66fbe98f273u64);
const K2: W64 = w64(0x9ae16a3b2f90404fu64);
const K3: W64 = w64(0xc949d7c7509e6557u64);

/**
# Safety
`s` has to point to at least 8 bytes of available data.
*/
#[inline]
unsafe fn fetch64(s: *const u8) -> W64 {
    w64((s as *const u64).read_unaligned().to_le())
}

/**
# Safety
`s` has to point to at least 4 bytes of available data.
*/
#[inline]
unsafe fn fetch32(s: *const u8) -> W32 {
    w32((s as *const u32).read_unaligned().to_le())
}

#[inline]
fn rotate(v: W64, n: u32) -> W64 {
    debug_assert!(n > 0);
    // Look, ma, I have real rotate!
    // rotate_right for Wrapping is yet unstable, so we unwrap and wrap it back.
    w64(v.0.rotate_right(n))
}

fn hash_len16(u: W64, v: W64) -> W64 {
    hash128_to_64(u, v)
}

// Hash 128 input bits down to 64 bits of output.
// This is intended to be a reasonably good hash function.
#[inline]
fn hash128_to_64(l: W64, h: W64) -> W64 {
    const K_MUL: W64 = w64(0x9ddfea08eb382d69u64);
    let mut a = (h ^ l) * K_MUL;
    a ^= a >> 47;
    let mut b = (h ^ a) * K_MUL;
    b ^= b >> 47;
    b * K_MUL
}

fn hash_len0to16(data: &[u8]) -> W64 {
    let len = data.len();
    let s = data.as_ptr();

    if len > 8 {
        // It is ok as len > 8.
        unsafe {
            let a = fetch64(s);
            let b = fetch64(s.add(len).sub(8));
            b ^ hash_len16(a, rotate(b + w64(len as u64), len as u32))
        }
    } else if len >= 4 {
        // It is ok as len > 4.
        unsafe {
            let a = fetch32(s).0 as u64;

            hash_len16(
                w64((len as u64) + (a << 3)),
                w64(fetch32(s.add(len).sub(4)).0.into()),
            )
        }
    } else if len > 0 {
        // TODO make sure checks are eliminated by the compiler.
        let a: u8 = data[0];
        let b: u8 = data[len >> 1];
        let c: u8 = data[len - 1];
        let y = w64(a as u64) + w64((b as u64) << 8);
        let z = w64(((len as u32) + ((c as u32) << 2)) as u64);

        shift_mix((y * K2) ^ (z * K3)) * K2
    } else {
        K2
    }
}

/*
This function is unsafe because it will read incorrect memory when data.len() < 17.
*/
unsafe fn hash_len17to32(data: &[u8]) -> W64 {
    let s = data.as_ptr();
    let len = data.len();
    debug_assert!(len > 16);

    let a = fetch64(s) * K1;
    let b = fetch64(s.add(8));
    let c = fetch64(s.add(len).sub(8)) * K2;
    let d = fetch64(s.add(len).sub(16)) * K0;
    hash_len16(
        rotate(a - b, 43) + rotate(c, 30) + d,
        a + rotate(b ^ K3, 20) - c + w64(len as u64),
    )
}

/*
This function is unsafe because it will read incorrect memory when data.len() < 33.
*/
unsafe fn hash_len33to64(data: &[u8]) -> W64 {
    let s = data.as_ptr();
    let len = data.len();
    debug_assert!(len > 32);

    let mut z = fetch64(s.add(24));
    let mut a = fetch64(s) + K0 * (w64(len as u64) + fetch64(s.add(len).sub(16)));
    let mut b = rotate(a + z, 52);
    let mut c = rotate(a, 37);
    a += fetch64(s.add(8));
    c += rotate(a, 7);
    a += fetch64(s.add(16));

    let vf = a + z;
    let vs = b + rotate(a, 31) + c;
    a = fetch64(s.add(16)) + fetch64(s.add(len).sub(32));
    z = fetch64(s.add(len).sub(8));
    b = rotate(a + z, 52);
    c = rotate(a, 37);
    a += fetch64(s.add(len).sub(24));
    c += rotate(a, 7);
    a += fetch64(s.add(len).sub(16));
    let wf = a + z;
    let ws = b + rotate(a, 31) + c;
    let r = shift_mix(K2 * (vf + ws) + K0 * (wf + vs));
    shift_mix(vs + r * K0) * K2
}

/* This function is unsafe because it reads 32 bytes starting from s. */
unsafe fn weak_hash_len32_with_seeds(s: *const u8, a: W64, b: W64) -> (W64, W64) {
    weak_hash_len32_with_seeds_(
        fetch64(s),
        fetch64(s.add(8)),
        fetch64(s.add(16)),
        fetch64(s.add(24)),
        a,
        b,
    )
}

fn weak_hash_len32_with_seeds_(
    w: W64,
    x: W64,
    y: W64,
    z: W64,
    mut a: W64,
    mut b: W64,
) -> (W64, W64) {
    a += w;
    b = rotate(b + a + z, 21);
    let c = a;
    a += x + y;
    b += rotate(a, 44);
    (a + z, b + c)
}

fn shift_mix(val: W64) -> W64 {
    val ^ (val >> 47)
}

/**
ClickHouse's version of the CityHash64 hash.  It is used in the
query language to process user data.
*/
pub fn cityhash64(data: &[u8]) -> u64 {
    unsafe {
        if data.len() <= 32 {
            if data.len() <= 16 {
                return hash_len0to16(data).0;
            } else {
                return hash_len17to32(data).0;
            }
        } else if data.len() <= 64 {
            return hash_len33to64(data).0;
        }

        let mut s = data.as_ptr();
        let mut len = data.len();

        // For strings over 64 bytes we hash the end first, and then as we
        // loop we keep 56 bytes of state: v, w, x, y, and z.
        let mut x = fetch64(s);
        let mut y = fetch64(s.add(len).sub(16)) ^ K1;
        let mut z = fetch64(s.add(len).sub(56)) ^ K0;

        let mut v: (W64, W64) = weak_hash_len32_with_seeds(s.add(len).sub(64), w64(len as u64), y);
        let mut w: (W64, W64) =
            weak_hash_len32_with_seeds(s.add(len).sub(32), K1 * w64(len as u64), K0);

        z += shift_mix(v.1) * K1;
        x = rotate(z + x, 39) * K1;
        y = rotate(y, 33) * K1;

        len = (len - 1) & !63;

        while {
            x = rotate(x + y + v.0 + fetch64(s.add(16)), 37) * K1;
            y = rotate(y + v.1 + fetch64(s.add(48)), 42) * K1;
            x ^= w.1;
            y ^= v.0;
            z = rotate(z ^ w.0, 33);
            v = weak_hash_len32_with_seeds(s, v.1 * K1, x + w.0);
            w = weak_hash_len32_with_seeds(s.add(32), z + w.1, y);
            core::mem::swap(&mut z, &mut x);

            s = s.add(64);
            len -= 64;

            len != 0
        } { /* EMPTY */ }

        hash_len16(
            hash_len16(v.0, w.0) + shift_mix(y) * K1 + z,
            hash_len16(v.1, w.1) + x,
        )
        .0
    }
}

fn city_murmur(data: &[u8], seed: U128) -> U128 {
    let mut s = data.as_ptr();
    let len = data.len();

    let mut a = w64(seed.first);
    let mut b = w64(seed.second);
    let mut c: W64;
    let mut d: W64;
    let mut l = (len as isize) - 16;

    if l <= 0 {
        // len <= 16
        a = shift_mix(a * K1) * K1;
        c = b * K1 + hash_len0to16(data);
        // It is safe as read of 8 bytes is guarded by `len >= 8` condition.
        d = unsafe { shift_mix(a + (if len >= 8 { fetch64(s) } else { c })) };
    } else {
        // len > 16
        // It is safe because len > 16 and that's enough
        unsafe {
            c = hash_len16(fetch64(s.add(len).sub(8)) + K1, a);
            d = hash_len16(b + w64(len as u64), c + fetch64(s.add(len).sub(16)));
            a += d;
            while {
                a ^= shift_mix(fetch64(s) * K1) * K1;
                a *= K1;
                b ^= a;
                c ^= shift_mix(fetch64(s.add(8)) * K1) * K1;
                c *= K1;
                d ^= c;
                s = s.add(16);
                l -= 16;
                l > 0
            } { /* EMPTY */ }
        }
    }
    a = hash_len16(a, c);
    b = hash_len16(d, b);
    U128::from_w64(a ^ b, hash_len16(b, a))
}

fn cityhash128_with_seed(data: &[u8], seed: U128) -> U128 {
    let mut s = data.as_ptr();
    let mut len = data.len();

    unsafe {
        // TODO: it may be inlined to the cityhash128
        if len < 128 {
            return city_murmur(data, seed);
        }

        // We expect len >= 128 to be the common case.  Keep 56 bytes of state:
        // v, w, x, y, and z.
        let mut x = w64(seed.first);
        let mut y = w64(seed.second);
        let mut z = w64(len as u64) * K1;
        let mut v = (w64(0), w64(0));
        v.0 = rotate(y ^ K1, 49) * K1 + fetch64(s);
        v.1 = rotate(v.0, 42) * K1 + fetch64(s.add(8));
        let mut w = (
            rotate(y + z, 35) * K1 + x,
            rotate(x + fetch64(s.add(88)), 53) * K1,
        );

        while {
            x = rotate(x + y + v.0 + fetch64(s.add(16)), 37) * K1;
            y = rotate(y + v.1 + fetch64(s.add(48)), 42) * K1;
            x ^= w.1;
            y ^= v.0;
            z = rotate(z ^ w.0, 33);
            v = weak_hash_len32_with_seeds(s, v.1 * K1, x + w.0);
            w = weak_hash_len32_with_seeds(s.add(32), z + w.1, y);
            core::mem::swap(&mut z, &mut x);
            s = s.add(64);
            x = rotate(x + y + v.0 + fetch64(s.add(16)), 37) * K1;
            y = rotate(y + v.1 + fetch64(s.add(48)), 42) * K1;
            x ^= w.1;
            y ^= v.0;
            z = rotate(z ^ w.0, 33);
            v = weak_hash_len32_with_seeds(s, v.1 * K1, x + w.0);
            w = weak_hash_len32_with_seeds(s.add(32), z + w.1, y);
            core::mem::swap(&mut z, &mut x);
            s = s.add(64);
            len -= 128;

            len >= 128
        } { /* EMPTY */ }

        y += rotate(w.0, 37) * K0 + z;
        x += rotate(v.0 + z, 49) * K0;

        // If 0 < len < 128, hash up to 4 chunks of 32 bytes each from the end of s.
        let mut tail_done: usize = 0;
        while tail_done < len {
            tail_done += 32;
            y = rotate(y - x, 42) * K0 + v.1;
            w.0 += fetch64(s.add(len).sub(tail_done).add(16));
            x = rotate(x, 49) * K0 + w.0;
            w.0 += v.0;
            v = weak_hash_len32_with_seeds(s.add(len).sub(tail_done), v.0, v.1);
        }
        // At this point our 48 bytes of state should contain more than
        // enough information for a strong 128-bit hash.  We use two
        // different 48-byte-to-8-byte hashes to get a 16-byte final result.
        x = hash_len16(x, v.0);
        y = hash_len16(y, w.0);

        U128::from_w64(hash_len16(x + v.1, w.1) + y, hash_len16(x + w.1, y + v.1))
    }
}

/**
ClickHouse's version of the CityHash128 hash.  It is used in the
ClickHouse protocol.

## Returned value
This function returns the [`U128`] struct that follows the
original C++ version, even though Rust has native `u128` type.
`From<u128>` and `Into<u128>` are implemented for this type.
*/
pub fn cityhash128(data: &[u8]) -> U128 {
    let s = data.as_ptr();
    let len = data.len();
    unsafe {
        if len >= 16 {
            cityhash128_with_seed(
                &data[16..],
                U128::from_w64(fetch64(s) ^ K3, fetch64(s.add(8))),
            )
        } else if data.len() >= 8 {
            cityhash128_with_seed(
                b"",
                U128::from_w64(
                    fetch64(s) ^ (w64(len as u64) * K0),
                    fetch64(s.add(len).sub(8)) ^ K1,
                ),
            )
        } else {
            cityhash128_with_seed(data, U128::from_w64(K0, K1))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{cityhash128, cityhash64, U128};

    #[test]
    fn test_64_len0() {
        assert_eq!(cityhash64(b""), 11160318154034397263);
    }

    #[test]
    fn test_64_len1() {
        assert_eq!(cityhash64(b"1"), 11413460447292444913);
    }

    #[test]
    fn test_64_len2() {
        assert_eq!(cityhash64(b"12"), 12074748272894662792);
    }

    #[test]
    fn test_64_len3() {
        assert_eq!(cityhash64(b"abc"), 4220206313085259313);
    }

    #[test]
    fn test_64_len4() {
        assert_eq!(cityhash64(b"1234"), 11914632649014994877);
    }

    #[test]
    fn test_64_len5() {
        assert_eq!(cityhash64(b"12345"), 16429329056539592968);
    }

    #[test]
    fn test_64_len6() {
        assert_eq!(cityhash64(b"123456"), 9260297286307356373);
    }

    #[test]
    fn test_64_len7() {
        assert_eq!(cityhash64(b"1234567"), 11025202622668490255);
    }

    #[test]
    fn test_64_len8() {
        assert_eq!(cityhash64(b"12345678"), 7177601938557627951);
    }

    #[test]
    fn test_64_len9() {
        assert_eq!(cityhash64(b"123456789"), 12390271160407166709);
    }

    #[test]
    fn test_64_len10() {
        assert_eq!(cityhash64(b"1234567890"), 11159486737701695049);
    }

    #[test]
    fn test_64_len11() {
        assert_eq!(cityhash64(b"1234567890A"), 12461606063103015484);
    }

    #[test]
    fn test_64_len12() {
        assert_eq!(cityhash64(b"1234567890Ab"), 3962957222420222636);
    }

    #[test]
    fn test_64_len13() {
        assert_eq!(cityhash64(b"1234567890Abc"), 10943934074830884361);
    }

    #[test]
    fn test_64_len14() {
        assert_eq!(cityhash64(b"1234567890AbcD"), 14566583638543629997);
    }

    #[test]
    fn test_64_len15() {
        assert_eq!(cityhash64(b"1234567890AbcDE"), 1470766631700230904);
    }

    #[test]
    fn test_64_len16() {
        assert_eq!(cityhash64(b"1234567890abcdef"), 10283158570132023530);
    }

    #[test]
    fn test_64_len17() {
        assert_eq!(cityhash64(b"4RNfAbDSysH78xK5s"), 16686325262955297357);
    }

    #[test]
    fn test_64_longer() {
        assert_eq!(
            cityhash64(b"1234567890abcdefghijklmnopqrstuvwxyz"),
            6062807976406716385
        );
    }

    #[test]
    fn test_64_len64() {
        let data = &b"7zxsqkZNsEoNfRz83hct4HH5ytE3SFvx0MX9ACbDDBZhtUcR30pGvmJIPAoXwJCq"[..];
        assert_eq!(data.len(), 64); // test validity
        assert_eq!(cityhash64(&data), 12341453991847893643);
    }

    #[test]
    fn test_64_len65() {
        let data = &b"DSDXf2J5gvPZWtzo4qdrdbXw6qGKkVuzrV7zEZA3x6xNnGdQdSTr7YocaJWpgDgzq"[..];
        assert_eq!(data.len(), 65); // test validity
        assert_eq!(cityhash64(data), 12363235829494951337);
    }

    #[test]
    fn test_64_verylong() {
        let data =
            &b"DMqhuXQxgAmJ9EOkT1n2lpzu7YD6zKc6ESSDWfJfohaQDwu0ba61bfGMiuS5GXpr0bIVcCtLwRtIVGmK"[..];
        assert_eq!(data.len(), 80); // test validity
        assert_eq!(cityhash64(data), 12512298373611890505);
    }

    #[test]
    fn test_64_binary() {
        let data = b"\xe4x\x98\xa4*\xd7\xdc\x02p.\xdeI$\x9fp\xd4\xe3\xd7\xe7L\x86<5h75\xdf0B\x16\xe0\x86\xbeP\xb1rL\x8b\x07\x14!\x9e\xf5\xe0\x9cN\xa5\xfdJ]\xd8J\xc1\xc2.\xe6\xae\x14\xad^sW\x15&";
        assert_eq!(cityhash64(data.as_ref()), 5932484233276644677);
    }

    #[test]
    fn test_from_u128() {
        let v = U128::from(0x11212312341234512345612345671234u128);
        assert_eq!(v.first, 0x2345612345671234u64);
        assert_eq!(v.second, 0x1121231234123451u64);
    }

    #[test]
    fn test_into_u128() {
        let v: u128 = U128::new(0x2345612345671234u64, 0x1121231234123451u64).into();
        assert_eq!(v, 0x11212312341234512345612345671234u128);
    }

    /*
     * The test_128_* numbers are generated by a custom binary calling CityHash128.
     */
    #[test]
    fn test_128_len0() {
        assert_eq!(
            cityhash128(b""),
            U128::new(4463240938071824939, 4374473821787594281)
        );
    }

    #[test]
    fn test_128_len1() {
        assert_eq!(
            cityhash128(b"1"),
            U128::new(6359294370932160835, 9352172043616825891)
        );
    }

    #[test]
    fn test_128_len2() {
        assert_eq!(
            cityhash128(b"12"),
            U128::new(16369832005849840265, 11285803613326688650)
        );
    }

    #[test]
    fn test_128_len3() {
        assert_eq!(
            cityhash128(b"123"),
            U128::new(11385344155619871181, 565130349297615695)
        );
    }

    #[test]
    fn test_128_len4() {
        assert_eq!(
            cityhash128(b"1234"),
            U128::new(2764810728135862028, 5901424084875196719)
        );
    }

    #[test]
    fn test_128_len5() {
        assert_eq!(
            cityhash128(b"12345"),
            U128::new(11980518989907363833, 93456746504981291)
        );
    }

    #[test]
    fn test_128_len6() {
        assert_eq!(
            cityhash128(b"123456"),
            U128::new(2350911489181485812, 12095241732236332703)
        );
    }

    #[test]
    fn test_128_len7() {
        assert_eq!(
            cityhash128(b"1234567"),
            U128::new(10270309315532912023, 9823143772454143291)
        );
    }

    #[test]
    fn test_128_len8() {
        assert_eq!(
            cityhash128(b"12345678"),
            U128::new(2123262123519760883, 8251334461883709976)
        );
    }

    #[test]
    fn test_128_len9() {
        assert_eq!(
            cityhash128(b"123456789"),
            U128::new(14140762465907274276, 13893707330375041594)
        );
    }

    #[test]
    fn test_128_len10() {
        assert_eq!(
            cityhash128(b"1234567890"),
            U128::new(8211333661328737896, 17823093577549856754)
        );
    }

    #[test]
    fn test_128_len11() {
        assert_eq!(
            cityhash128(b"1234567890A"),
            U128::new(1841684041954399514, 6623964278873157363)
        );
    }

    #[test]
    fn test_128_len12() {
        assert_eq!(
            cityhash128(b"1234567890Ab"),
            U128::new(3349064628685767173, 12952593207096460945)
        );
    }

    #[test]
    fn test_128_len13() {
        assert_eq!(
            cityhash128(b"1234567890Abc"),
            U128::new(6572961695122645386, 13774858861848724400)
        );
    }

    #[test]
    fn test_128_len14() {
        assert_eq!(
            cityhash128(b"1234567890AbcD"),
            U128::new(18041930573402443112, 5778672772533284640)
        );
    }

    #[test]
    fn test_128_len15() {
        assert_eq!(
            cityhash128(b"1234567890AbcDE"),
            U128::new(11266190325599732773, 348002394938205539)
        );
    }

    #[test]
    fn test_128_len16() {
        assert_eq!(
            cityhash128(b"1234567890AbcDEF"),
            U128::new(15073733098592741404, 5913034415582713572)
        );
    }

    #[test]
    fn test_128_long() {
        assert_eq!(
            cityhash128(b"this is somewhat long string"),
            U128::new(2957911805285034456, 6923665615086076251)
        );
    }

    #[test]
    fn test_128_longer() {
        assert_eq!(
            cityhash128(
                b"DMqhuXQxgAmJ9EOkT1n2lpzu7YD6zKc6ESSDWfJfohaQDwu0ba61bfGMiuS5GXpr0bIVcCtLwRtIVGmK"
            ),
            U128::new(9681404383092874918, 15631953994107571989)
        );
    }

    #[test]
    fn test_128_binary() {
        let data = b"\xe4x\x98\xa4*\xd7\xdc\x02p.\xdeI$\x9fp\xd4\xe3\xd7\xe7L\x86<5h75\xdf0B\x16\xe0\x86\xbeP\xb1rL\x8b\x07\x14!\x9e\xf5\xe0\x9cN\xa5\xfdJ]\xd8J\xc1\xc2.\xe6\xae\x14\xad^sW\x15&";
        assert_eq!(
            cityhash128(data.as_ref()),
            U128::new(5907140908903622203, 10088853506155899265)
        );
    }
}
