#![no_main]
use libfuzzer_sys::fuzz_target;
use mptcp_rs::wire::mptcp::{MptcpOption, encode, parse};
use mptcp_rs::wire::tcp_options::{TcpOpt, walk};

fn check(opt: &[u8]) {
    if let Ok(o) = parse(opt) {
        // Unknown keeps no payload, so it cannot round-trip (and is never sent).
        if matches!(o, MptcpOption::Unknown { .. }) {
            return;
        }
        let mut out = [0u8; 40];
        let n = encode(&o, &mut out).expect("encode of a parsed option succeeds");
        assert_eq!(parse(&out[..n]), Ok(o));
    }
}

/// A well-formed-header option of one of the new subtypes (ADD_ADDR, REMOVE_ADDR, MP_PRIO,
/// MP_TCPRST): `sel` picks subtype and length, `b` fills the rest.
fn synth(sel: u8, b: &[u8]) -> Vec<u8> {
    let n = usize::from(sel / 4);
    let (st, len) = match sel % 4 {
        0 => (3, [8, 10, 16, 18, 20, 22, 28, 30][n % 8]),
        1 => (4, 4 + n % 37),
        2 => (5, 3),
        _ => (8, 4),
    };
    let mut o = vec![0; len];
    for (i, x) in o[2..].iter_mut().enumerate() {
        *x = b.get(i).copied().unwrap_or(0);
    }
    o[0] = 30;
    o[1] = len as u8;
    // E=1 exactly for the lengths without an HMAC.
    let low = if st == 3 {
        o[2] & 0x0e | u8::from(matches!(len, 8 | 10 | 20 | 22))
    } else {
        o[2] & 0x0f
    };
    o[2] = st << 4 | low;
    o
}

fuzz_target!(|data: &[u8]| {
    check(data);
    if let Some((&sel, rest)) = data.split_first() {
        check(&synth(sel, rest));
    }
    for o in walk(data).flatten() {
        if let TcpOpt::Mptcp(s) = o {
            check(s);
        }
    }
});
