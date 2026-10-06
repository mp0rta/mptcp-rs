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

fuzz_target!(|data: &[u8]| {
    check(data);
    for o in walk(data).flatten() {
        if let TcpOpt::Mptcp(s) = o {
            check(s);
        }
    }
});
