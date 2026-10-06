//! Crypto helpers: MPTCP key token/IDSN (RFC 8684 §3.1), MP_JOIN HMAC (§3.2)
//! and the RFC 6528 initial sequence number generator.
//!
//! Test vectors come from an independent implementation:
//!
//! ```bash
//! python3 - <<'PY'
//! import hashlib, hmac, struct
//! for k in (0x0102030405060708, 0xfedcba9876543210, 0):
//!     d = hashlib.sha256(struct.pack('>Q', k)).digest()
//!     print('token_idsn', hex(k), d[:4].hex(), d[24:].hex())
//! ka, kb, ra, rb = 0x0102030405060708, 0x1112131415161718, 0xa1a2a3a4, 0xb1b2b3b4
//! print('hmac_a', hmac.new(struct.pack('>QQ', ka, kb), struct.pack('>II', ra, rb), hashlib.sha256).hexdigest())
//! print('hmac_b', hmac.new(struct.pack('>QQ', kb, ka), struct.pack('>II', rb, ra), hashlib.sha256).hexdigest())
//! PY
//! ```

use crate::{Instant, SeqNum};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};

/// RFC 8684 §3.1: token = most significant 32 bits of SHA-256(key),
/// IDSN = least significant 64 bits.
pub fn key_token_idsn(key: u64) -> (u32, u64) {
    let d = Sha256::digest(key.to_be_bytes());
    let token = u32::from_be_bytes(d[..4].try_into().unwrap());
    let idsn = u64::from_be_bytes(d[24..].try_into().unwrap());
    (token, idsn)
}

/// RFC 8684 §3.2: HMAC-SHA256, key = `key_self || key_peer`,
/// message = `nonce_self || nonce_peer`. Callers truncate.
pub fn join_hmac(key_self: u64, key_peer: u64, nonce_self: u32, nonce_peer: u32) -> [u8; 32] {
    let mut key = [0u8; 16];
    key[..8].copy_from_slice(&key_self.to_be_bytes());
    key[8..].copy_from_slice(&key_peer.to_be_bytes());
    let mut msg = [0u8; 8];
    msg[..4].copy_from_slice(&nonce_self.to_be_bytes());
    msg[4..].copy_from_slice(&nonce_peer.to_be_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC accepts any key length");
    mac.update(&msg);
    mac.finalize().into_bytes().into()
}

/// RFC 6528 ISN generator: `ISN = M + F(local, remote, secret)`.
/// No `Debug` impl: the secret must never be logged.
pub struct IsnGenerator {
    secret: [u8; 16],
}

impl IsnGenerator {
    pub fn new(secret: [u8; 16]) -> Self {
        Self { secret }
    }

    pub fn isn(&self, now: Instant, local: SocketAddr, remote: SocketAddr) -> SeqNum {
        let mut h = Sha256::new();
        for a in [local, remote] {
            match a.ip() {
                IpAddr::V4(ip) => h.update(ip.octets()),
                IpAddr::V6(ip) => h.update(ip.octets()),
            }
            h.update(a.port().to_be_bytes());
        }
        h.update(self.secret);
        let d = h.finalize();
        let f = u32::from_be_bytes(d[..4].try_into().unwrap());
        // M: 4 us ticks, wrapping truncation to 32 bits.
        let m = (now.as_nanos() / 4000) as u32;
        SeqNum(m.wrapping_add(f))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn token_idsn_matches_vectors() {
        for (k, token, idsn) in [
            (0x0102030405060708u64, "66840dda", "f5a101d3d29d6f72"),
            (0xfedcba9876543210, "18f9781b", "280818bf0fa7e28e"),
            (0, "af5570f5", "e5b2328de0e83dfc"),
        ] {
            let (t, i) = key_token_idsn(k);
            assert_eq!(hex(&t.to_be_bytes()), token);
            assert_eq!(hex(&i.to_be_bytes()), idsn);
        }
    }

    #[test]
    fn join_hmac_matches_vectors() {
        let (ka, kb, ra, rb) = (
            0x0102030405060708,
            0x1112131415161718,
            0xa1a2a3a4,
            0xb1b2b3b4,
        );
        assert_eq!(
            hex(&join_hmac(ka, kb, ra, rb)),
            "53037f2899475529844115fd07e665d23d3554fb8dde7551287562b1aa8e53de"
        );
        assert_eq!(
            hex(&join_hmac(kb, ka, rb, ra)),
            "864b40428762fd06fa24bb3c5ea12c1bbf6546e7aace88911139aa8f77f90286"
        );
    }

    #[test]
    fn isn_differs_by_tuple_and_advances_with_time() {
        let g = IsnGenerator::new([7; 16]);
        let now = Instant::from_nanos(123_456_789_000);
        let a: SocketAddr = "10.0.0.1:50000".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:80".parse().unwrap();
        let c: SocketAddr = "[2001:db8::1]:80".parse().unwrap();
        let base = g.isn(now, a, b);
        assert_ne!(base, g.isn(now, a, c));
        assert_ne!(base, g.isn(now, b, a));
        assert_ne!(base, g.isn(now, "10.0.0.1:50001".parse().unwrap(), b));
        assert_ne!(base, IsnGenerator::new([8; 16]).isn(now, a, b));
        let later = Instant::from_nanos(now.as_nanos() + 4_000);
        assert_eq!(g.isn(later, a, b), base.wrapping_add(1));
    }
}
