//! The server's MP_CAPABLE negotiation table (M4a plan Task 5, spec G2b), row by row, against
//! a scripted client (`server_tests::Script`).
use super::super::server_tests::*;
use super::*;
use crate::wire::mptcp::{CAP_A, CAP_B, CAP_C, Dss};

/// The SYN/ACK's MP_CAPABLE: length 12, version 1, flags exactly H (our C=0), our key.
fn synack_cap() -> Vec<Vec<u8>> {
    vec![cap(1, CAP_H, Some(SERVER_KEY), None, None)]
}

/// A listener with MPTCP on, after a valid v1 SYN.
fn started() -> Script {
    let mut s = Script::new(true);
    let synack = s.syn(&syn_cap(1, CAP_H));
    assert_eq!(mptcp_of(&synack), synack_cap());
    s
}

/// Fallback: `Accepted { mptcp: false }`, `payload` readable as plain TCP, and no MPTCP option
/// in `out` (the server's answer to the final ACK) or later.
fn fell_back(s: &mut Script, out: &[Vec<u8>], payload: &[u8]) {
    assert_eq!(s.events(), [Event::Accepted { mptcp: false }]);
    let c = &s.ep.conns[&ConnectionHandle(0)];
    let state = c.hooks.negotiation.as_ref().map(|n| n.state);
    assert!(matches!(state, None | Some(State::FellBack)), "{state:?}");
    assert!(c.hooks.data.is_none());
    assert!(out.iter().all(|p| mptcp_of(p).is_empty()));
    assert_eq!(s.read_all(), payload);
    s.assert_plain_after();
}

/// Confirmed: `Accepted { mptcp: true }` and a DSS DATA_ACK for `acked` octets sent at once.
fn confirmed(s: &mut Script, out: &[Vec<u8>], acked: u64) {
    assert_eq!(s.events(), [Event::Accepted { mptcp: true }]);
    assert_eq!(s.negotiation().state, State::Confirmed);
    assert_eq!(s.negotiation().peer_key, Some(CLIENT_KEY));
    let ack = dss_ack(client_idsn().wrapping_add(1 + acked));
    assert!(
        out.iter().any(|p| mptcp_of(p) == [ack.clone()]),
        "DATA_ACK due"
    );
}

fn has_rst(out: &[Vec<u8>]) -> bool {
    out.iter()
        .any(|p| packet::parse(p).unwrap().flags.contains(TcpFlags::RST))
}

#[test]
fn server_syn_no_capable_plain() {
    let mut s = Script::new(true);
    assert!(mptcp_of(&s.syn(&[])).is_empty());
    assert_eq!(s.ep.keys.len(), 1, "no key drawn");
    let out = s.send(65535, &ack_cap(CAP_H, None), &[]);
    fell_back(&mut s, &out, &[]);
}

#[test]
fn server_syn_listener_without_mptcp_plain() {
    let mut s = Script::new(false);
    assert!(mptcp_of(&s.syn(&syn_cap(1, CAP_H))).is_empty());
    assert!(s.ep.tokens.is_empty());
    let out = s.send(65535, &ack_cap(CAP_H, None), &[]);
    fell_back(&mut s, &out, &[]);
}

/// More than one MP_CAPABLE, length ≠ 4, version 0, A=1, B=1 or H=0 whatever D–G say:
/// plain TCP, no MP_CAPABLE in the SYN/ACK (RFC 8684 L942–944, L958–970, L972–982).
#[test]
fn server_syn_invalid_capable_plain() {
    let good = syn_cap(1, CAP_H);
    let cases = [
        [good.clone(), good.clone()].concat(),
        cap(0, CAP_H, Some(CLIENT_KEY), None, None),
        cap(1, CAP_H, Some(CLIENT_KEY), None, None),
        vec![30, 5, 0x01, CAP_H, 0],
        syn_cap(0, CAP_H),
        syn_cap(1, CAP_A | CAP_H),
        syn_cap(1, CAP_B | CAP_H),
        syn_cap(1, 0),
        syn_cap(1, CAP_C),
        syn_cap(1, 0x02),
        syn_cap(1, 0x10),
    ];
    for options in cases {
        let mut s = Script::new(true);
        assert!(mptcp_of(&s.syn(&options)).is_empty(), "{options:?}");
        assert!(s.ep.tokens.is_empty());
        let out = s.send(65535, &ack_cap(CAP_H, None), &[]);
        fell_back(&mut s, &out, &[]);
    }
}

/// Version ≥ 1, length 4, A=0, B=0, H=1: D–G are not chosen, C is recorded; the SYN/ACK has
/// flags exactly H.
#[test]
fn server_syn_v1_capable_answered() {
    for (flags, peer_c) in [(CAP_H, false), (CAP_H | 0x1e, false), (CAP_H | CAP_C, true)] {
        let mut s = Script::new(true);
        assert_eq!(mptcp_of(&s.syn(&syn_cap(1, flags))), synack_cap());
        assert_eq!(s.negotiation().peer_c, peer_c);
        assert_eq!(s.negotiation().state, State::AwaitingKey);
        assert_eq!(s.ep.tokens.len(), 1);
        let out = s.send(65535, &ack_cap(CAP_H, None), &[]);
        confirmed(&mut s, &out, 0);
    }
}

/// The highest version we support answers a higher one (RFC 8684 L716–722).
#[test]
fn server_syn_version_2_answered_v1() {
    for version in [2, 15] {
        let mut s = Script::new(true);
        assert_eq!(mptcp_of(&s.syn(&syn_cap(version, CAP_H))), synack_cap());
        let out = s.send(65535, &ack_cap(CAP_H, None), &[]);
        confirmed(&mut s, &out, 0);
    }
}

#[test]
fn server_syn_duplicate_same_synack() {
    let mut s = started();
    s.input(TcpFlags::SYN, C_ISN, 65535, &syn_cap(1, CAP_H), &[]);
    let out = s.output();
    assert_eq!(out.len(), 1);
    let again = packet::parse(&out[0]).unwrap();
    assert_eq!(again.flags, TcpFlags::SYN | TcpFlags::ACK);
    assert_eq!(again.seq.0, s.iss);
    assert_eq!(mptcp_of(&out[0]), synack_cap());
    assert_eq!((s.ep.conns.len(), s.ep.tokens.len()), (1, 1));
    let out = s.send(65535, &ack_cap(CAP_H, None), &[]);
    confirmed(&mut s, &out, 0);
}

/// The third ACK carries no MP_CAPABLE: fall back (RFC 8684 L993–999).
#[test]
fn server_final_ack_no_capable_falls_back() {
    let mut s = started();
    let out = s.send(65535, &[], &[]);
    fell_back(&mut s, &out, &[]);
}

#[test]
fn server_final_ack_no_capable_with_payload_falls_back() {
    let mut s = started();
    let out = s.send(65535, &[], b"hello");
    fell_back(&mut s, &out, b"hello");
}

/// A middlebox strips the third ACK's MP_CAPABLE and later options: TCP payload on later
/// segments is delivered as plain TCP, whatever MPTCP option it still carries.
#[test]
fn server_final_ack_stripped_then_tcp_payload_delivered() {
    let mut s = started();
    let out = s.send(65535, &[], &[]);
    assert_eq!(s.events(), [Event::Accepted { mptcp: false }]);
    let mut out = [out, s.send(65535, &[], b"plain ")].concat();
    out.extend(s.send(65535, &ack_cap(CAP_H, Some(4)), b"data"));
    assert!(out.iter().all(|p| mptcp_of(p).is_empty()));
    assert_eq!(s.read_all(), b"plain data");
    s.assert_plain_after();
}

#[test]
fn server_final_ack_capable_20_confirms() {
    let mut s = started();
    let out = s.send(65535, &ack_cap(CAP_H, None), &[]);
    confirmed(&mut s, &out, 0);
    assert!(!s.negotiation().peer_dss_seen);
}

/// The third ACK was lost: the first data carries MP_CAPABLE with data parameters in place of a
/// DSS (RFC 8684 L836–855), mapping SSN 1 to the client's IDSN + 1.
#[test]
fn server_final_ack_capable_22_confirms_with_mapping() {
    let mut s = started();
    let out = s.send(65535, &ack_cap(CAP_H, Some(5)), b"hello");
    confirmed(&mut s, &out, 5);
    assert!(s.negotiation().peer_dss_seen);
    assert_eq!(s.read_all(), b"hello");
}

/// C=1 on a validated confirming MP_CAPABLE: no join to the client's initial address and
/// port (RFC 8684 L924–932).
#[test]
fn server_final_ack_c1_accepted() {
    for (form, payload) in [(None, &b""[..]), (Some(5), &b"hello"[..])] {
        let mut s = started();
        assert!(!s.negotiation().peer_c);
        let out = s.send(65535, &ack_cap(CAP_H | CAP_C, form), payload);
        confirmed(&mut s, &out, payload.len() as u64);
        assert!(s.negotiation().peer_c);
        let (now, h) = (s.now, ConnectionHandle(0));
        let (local, remote) = ("10.0.0.2".parse().unwrap(), CLIENT.parse().unwrap());
        let add = s.ep.add_subflow(now, h, local, remote, 1500, false);
        assert_eq!(add, Err(AddSubflowError::PeerForbidsJoin));
    }
}

/// Every way `capable_ack_ok` fails, each on its own, on both forms: fall back (RFC 8684
/// L877–883, L958–970).
#[test]
fn server_final_ack_invalid_capable_falls_back() {
    let keys = (Some(CLIENT_KEY), Some(SERVER_KEY));
    let mut cases = Vec::new();
    for form in [None, Some(5)] {
        let payload = if form.is_some() {
            &b"hello"[..]
        } else {
            &b""[..]
        };
        for (version, flags) in [
            (0, CAP_H),
            (2, CAP_H),
            (1, CAP_A | CAP_H),
            (1, CAP_B | CAP_H),
            (1, 0),
            (1, CAP_H | 0x10),
        ] {
            cases.push((cap(version, flags, keys.0, keys.1, form), payload));
        }
        let wrong = Some(SERVER_KEY ^ 1);
        cases.push((cap(1, CAP_H, keys.0, wrong, form), payload));
    }
    // The length for the form: 20 with payload, 22 without, 24 (checksum).
    cases.push((ack_cap(CAP_H, None), b"hello"));
    cases.push((ack_cap(CAP_H, Some(5)), b""));
    let c = MpCapable {
        version: 1,
        flags: CAP_H,
        sender_key: keys.0,
        receiver_key: keys.1,
        data_len: Some(5),
        checksum: Some(0),
    };
    let mut c24 = [0; 24];
    mptcp::encode(&MptcpOption::Capable(c), &mut c24).unwrap();
    cases.push((c24.to_vec(), b"hello"));
    for (option, payload) in cases {
        let mut s = started();
        let out = s.send(65535, &option, payload);
        fell_back(&mut s, &out, payload);
    }
}

#[test]
fn server_final_ack_two_capables_falls_back() {
    let mut s = started();
    let two = [ack_cap(CAP_H, None), ack_cap(CAP_H, None)].concat();
    let out = s.send(65535, &two, &[]);
    fell_back(&mut s, &out, &[]);
}

#[test]
fn server_final_ack_dss_without_capable_falls_back() {
    let mut s = started();
    let out = s.send(65535, &dss_ack(server_idsn().wrapping_add(1)), &[]);
    fell_back(&mut s, &out, &[]);
}

/// A later MP_CAPABLE with data parameters is a DSS mapping (RFC 8684 L857–873): after the
/// server's own DSS data, duplicated, and split over segments.
#[test]
fn server_later_capable_22_is_a_mapping() {
    let mut s = started();
    let out = s.send(65535, &ack_cap(CAP_H, None), &[]);
    confirmed(&mut s, &out, 0);
    // A repeated length-20 form changes nothing.
    assert!(!has_rst(&s.send(65535, &ack_cap(CAP_H, None), &[])));
    s.conn().write(b"srv").unwrap();
    let out = s.output();
    let dss = mptcp::parse(&mptcp_of(&out[0])[0]).unwrap();
    assert!(matches!(
        dss,
        MptcpOption::Dss(Dss {
            mapping: Some(_),
            ..
        })
    ));
    let split = ack_cap(CAP_H, Some(10));
    s.send(65535, &split, b"hello");
    // The same segment again, then the rest of the mapping.
    s.seq -= 5;
    s.send(65535, &split, b"hello");
    let out = s.send(65535, &split, b"world");
    assert!(!has_rst(&out));
    assert_eq!(s.read_all(), b"helloworld");
    let ack = dss_ack(client_idsn().wrapping_add(11));
    assert!(out.iter().any(|p| mptcp_of(p).contains(&ack)));
    assert!(s.negotiation().peer_dss_seen);
}

/// A later MP_CAPABLE that fails `capable_ack_ok` resets the listener's subflow, as a key
/// mismatch on a data mapping did; with or without data parameters.
#[test]
fn server_later_capable_invalid_resets_subflow() {
    let keys = (Some(CLIENT_KEY), Some(SERVER_KEY));
    let cases = [
        (
            cap(1, CAP_H, keys.0, Some(SERVER_KEY ^ 1), Some(5)),
            &b"hello"[..],
        ),
        (cap(1, CAP_A | CAP_H, keys.0, keys.1, Some(5)), b"hello"),
        (ack_cap(CAP_H, Some(5)), b""),
        (cap(0, CAP_H | CAP_C, keys.0, keys.1, None), b""),
        (cap(1, CAP_H, keys.0, Some(SERVER_KEY ^ 1), None), b""),
        (cap(1, CAP_B | CAP_H, keys.0, keys.1, None), b""),
        (ack_cap(CAP_H, None), b"hello"),
    ];
    for (option, payload) in cases {
        let mut s = started();
        let out = s.send(65535, &ack_cap(CAP_H, None), &[]);
        confirmed(&mut s, &out, 0);
        assert!(has_rst(&s.send(65535, &option, payload)), "{option:?}");
        assert!(!s.negotiation().peer_c, "C of an invalid option");
    }
}

/// A later MP_CAPABLE the parser rejects (length 5) is an invalid one too: the listener's
/// subflow is reset with the same RST as for an invalid well-formed one.
#[test]
fn server_later_capable_malformed_resets_subflow() {
    let rst_of = |option: &[u8]| {
        let mut s = started();
        let out = s.send(65535, &ack_cap(CAP_H, None), &[]);
        confirmed(&mut s, &out, 0);
        let out = s.send(65535, option, &[]);
        let rst = out.iter().find(|p| has_rst(std::slice::from_ref(p)));
        rst.map(|p| mptcp_of(p))
    };
    let invalid = rst_of(&cap(
        1,
        CAP_B | CAP_H,
        Some(CLIENT_KEY),
        Some(SERVER_KEY),
        None,
    ));
    assert!(invalid.is_some());
    assert_eq!(rst_of(&[30, 5, 1, 1, 0]), invalid);
}

/// A valid MP_CAPABLE on a final ACK whose option list is rejected (a malformed DSS, a second
/// DSS, a malformed TCP option): fallback, consistently: no MPTCP data state, the payload as
/// plain TCP, no MPTCP option afterwards, and C not taken.
#[test]
fn server_final_ack_rejected_options_fall_back() {
    let bad_dss = vec![30, 4, 0x20, 0xff];
    // A DSS with neither DATA_ACK nor mapping, twice.
    let dss = vec![30, 4, 0x20, 0];
    for (form, payload) in [(None, &b""[..]), (Some(5), &b"hello"[..])] {
        let good = ack_cap(CAP_H | CAP_C, form);
        for extra in [
            bad_dss.clone(),
            [dss.clone(), dss.clone()].concat(),
            vec![8, 1],
        ] {
            let mut s = started();
            let out = s.send(65535, &[good.clone(), extra.clone()].concat(), payload);
            assert!(!s.negotiation().peer_c, "{extra:?}");
            fell_back(&mut s, &out, payload);
            assert_eq!(s.negotiation().state, State::FellBack);
        }
    }
}
