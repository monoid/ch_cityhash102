/*
Copyright (c) 2021 Ivan Boldyrevx
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
#![no_std]

use core::num::Wrapping;

type w64 = Wrapping<u64>;
type w32 = Wrapping<u32>;

/** C++ CityHash-compatible uint128 type.  Please note that From<u128>
 * and Into<u128> are defined for this type.
 */
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U128 {
    pub lo: u64,
    pub hi: u64,
}

impl U128 {
    pub const fn new(lo: u64, hi: u64) -> Self {
        Self { lo, hi }
    }

    const fn from_w64(lo: w64, hi: w64) -> Self {
        Self { lo: lo.0, hi: hi.0 }
    }
}

impl From<u128> for U128 {
    fn from(source: u128) -> Self {
        Self {
            lo: source as u64,
            hi: (source >> 64) as u64,
        }
    }
}

impl From<U128> for u128 {
    fn from(val: U128) -> Self {
        (val.lo as u128) | ((val.hi as u128) << 64)
    }
}

const fn w64(v: u64) -> w64 {
    Wrapping(v)
}

const fn w32(v: u32) -> w32 {
    Wrapping(v)
}

// Some primes between 2^63 and 2^64 for various uses.
const K0: w64 = w64(0xc3a5c85c97cb3127u64);
const K1: w64 = w64(0xb492b66fbe98f273u64);
const K2: w64 = w64(0x9ae16a3b2f90404fu64);
const K3: w64 = w64(0xc949d7c7509e6557u64);

#[inline]
unsafe fn fetch64(s: *const u8) -> w64 {
    w64((s as *const u64).read_unaligned().to_le())
}

#[inline]
unsafe fn fetch32(s: *const u8) -> w32 {
    w32((s as *const u32).read_unaligned().to_le())
}

#[inline]
fn rotate(v: w64, n: u32) -> w64 {
    debug_assert!(n > 0);
    // Look, ma, I have real rotate!
    // rotate_right for Wrapping is yet unstable, so we unwrap and wrap it back.
    w64(v.0.rotate_right(n))
}

fn hash_len16(u: w64, v: w64) -> w64 {
    hash128_to_64(u, v)
}

// Hash 128 input bits down to 64 bits of output.
// This is intended to be a reasonably good hash function.
#[inline]
fn hash128_to_64(l: w64, h: w64) -> w64 {
    const K_MUL: w64 = w64(0x9ddfea08eb382d69u64);
    let mut a = (h ^ l) * K_MUL;
    a ^= a >> 47;
    let mut b = (h ^ a) * K_MUL;
    b ^= b >> 47;
    b * K_MUL
}

unsafe fn hash_len0to16(data: &[u8]) -> w64 {
    let len = data.len();
    let s = data.as_ptr();

    if len > 8 {
        let a = fetch64(s);
        let b = fetch64(s.add(len).sub(8));
        b ^ hash_len16(a, rotate(b + w64(len as u64), len as u32))
    } else if len >= 4 {
        let a = fetch32(s).0 as u64;

        hash_len16(
            w64((len as u64) + (a << 3)),
            w64(fetch32(s.add(len).sub(4)).0.into()),
        )
    } else if len > 0 {
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

unsafe fn hash_len17to32(data: &[u8]) -> w64 {
    let s = data.as_ptr();
    let len = data.len();

    let a = fetch64(s) * K1;
    let b = fetch64(s.add(8));
    let c = fetch64(s.add(len).sub(8)) * K2;
    let d = fetch64(s.add(len).sub(16)) * K0;
    hash_len16(
        rotate(a - b, 43) + rotate(c, 30) + d,
        a + rotate(b ^ K3, 20) - c + w64(len as u64),
    )
}

unsafe fn hash_len33to64(data: &[u8]) -> w64 {
    let s = data.as_ptr();
    let len = data.len();

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

unsafe fn weak_hash_len32_with_seeds(s: *const u8, a: w64, b: w64) -> (w64, w64) {
    weak_hash_len32_with_seeds_(
        fetch64(s),
        fetch64(s.add(8)),
        fetch64(s.add(16)),
        fetch64(s.add(24)),
        a,
        b,
    )
}

unsafe fn weak_hash_len32_with_seeds_(
    w: w64,
    x: w64,
    y: w64,
    z: w64,
    mut a: w64,
    mut b: w64,
) -> (w64, w64) {
    a += w;
    b = rotate(b + a + z, 21);
    let c = a;
    a += x + y;
    b += rotate(a, 44);
    (a + z, b + c)
}

fn shift_mix(val: w64) -> w64 {
    val ^ (val >> 47)
}

/**
ClickHouse's version of the CityHash64 hash.
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

        let mut v: (w64, w64) = weak_hash_len32_with_seeds(s.add(len).sub(64), w64(len as u64), y);
        let mut w: (w64, w64) =
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

unsafe fn city_murmur(data: &[u8], seed: U128) -> U128 {
    let mut s = data.as_ptr();
    let len = data.len();

    let mut a = w64(seed.lo);
    let mut b = w64(seed.hi);
    let mut c: w64;
    let mut d: w64;
    let mut l = (len as isize) - 16;

    if l <= 0 {
        // len <= 16
        a = shift_mix(a * K1) * K1;
        c = b * K1 + hash_len0to16(data);
        d = shift_mix(a + (if len >= 8 { fetch64(s) } else { c }));
    } else {
        // len > 16
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
        let mut x = w64(seed.lo);
        let mut y = w64(seed.hi);
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
    fn test_64_len8() {
        assert_eq!(cityhash64(b"12345678"), 7177601938557627951);
    }

    #[test]
    fn test_64_len9() {
        assert_eq!(cityhash64(b"123456789"), 12390271160407166709);
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
    fn test_from_u128() {
        let v = U128::from(0x11212312341234512345612345671234u128);
        assert_eq!(v.lo, 0x2345612345671234u64);
        assert_eq!(v.hi, 0x1121231234123451u64);
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
}
