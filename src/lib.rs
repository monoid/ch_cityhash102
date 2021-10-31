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
        // For strings over 64 bytes we hash the end first, and then as we
        // loop we keep 56 bytes of state: v, w, x, y, and z.
        let mut s = data.as_ptr();
        let mut len = data.len();

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

#[cfg(test)]
mod tests {
    use super::cityhash64;

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
}
