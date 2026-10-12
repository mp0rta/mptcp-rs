//! A sans-I/O userspace Multipath TCP v1 (RFC 8684) and TCP client stack.
//!
//! It implements the MPTCP protocol itself in userspace; it is not a helper for creating
//! kernel MPTCP sockets.
//!
//! The library does no I/O of its own. The caller feeds it received IP packets and the
//! current time, drains the IP packets it wants sent, and sleeps until its next timer.
//! Time ([`Instant`]) and randomness (a [`rand_core::CryptoRng`]) are injected, and the
//! crate contains no `unsafe` code.
//!
//! # Scope at 0.2.0
//!
//! Client role only. Implemented: MP_CAPABLE, DSS and DATA_ACK, MP_JOIN with multiple
//! subflows over IPv4 and IPv6 (including mixed families), a MinRTT scheduler with
//! reinjection, opportunistic retransmission and penalization, stale-subflow detection,
//! fallback to TCP (including the infinite mapping); CUBIC with HyStart++ and pacing, and
//! SACK-based loss recovery; plain TCP connections.
//!
//! Congestion control is chosen per connection with [`ConnectConfig::congestion_control`]:
//! [`CongestionControlKind::Cubic`] (the default) or [`CongestionControlKind::BbrV3`], BBRv3
//! (draft-ietf-ccwg-bbr-06, experimental). Every subflow runs the same controller, and the
//! subflows are not coupled: two subflows that share one bottleneck take about the share of
//! two TCP flows, with either controller.
//!
//! Path management is driven by the application: [`Endpoint::add_subflow`] joins a new path
//! (optionally with the backup bit), [`Endpoint::set_backup`] sends MP_PRIO,
//! [`Endpoint::set_local_backup`] changes only the local transmit policy,
//! [`Endpoint::close_subflow`] retires a subflow gracefully and
//! [`Endpoint::remove_address`] sends REMOVE_ADDR and resets the subflows on that address.
//! Received ADD_ADDR (with echo), REMOVE_ADDR and MP_PRIO surface as
//! [`Event::AddressAnnounced`], [`Event::AddressRemoved`] and [`Event::PeerPriority`], and
//! MP_TCPRST reasons arrive in [`Event::SubflowDown`]. [`Connection::abort`] sends
//! MP_FASTCLOSE; MP_FASTCLOSE is also honoured on receive.
//!
//! Not implemented yet: the server role, MPTCP checksums, MP_FAIL and RACK-TLP. Known
//! limitations: an application with no data left to send can still wait for a blackholed
//! subflow to be declared stale, and backup failover waits for the primary to become
//! unusable (see the README).
//!
//! # Usage
//!
//! [`Endpoint::connect_mptcp`] opens an MPTCP connection (falling back to TCP if the peer
//! does not support it); [`Endpoint::connect`] opens plain TCP. Then drive the endpoint:
//!
//! - [`Endpoint::handle_packet`] for each received IP packet;
//! - [`Endpoint::poll_transmit`] until it returns `None`, sending each packet it writes;
//! - [`Endpoint::poll_timeout`] for the next deadline, and [`Endpoint::handle_timeout`]
//!   when it passes;
//! - [`Endpoint::poll_event`] for [`Event`]s such as `Connected`, `SubflowUp` and `Closed`;
//! - [`Endpoint::connection`] for the [`Connection`], to [`write`](Connection::write),
//!   [`read`](Connection::read) and [`close`](Connection::close);
//! - [`Endpoint::add_subflow`] to join another local address once connected (see above for
//!   the other path-management calls).
//!
//! ```
//! use mptcp_rs::{ConnectConfig, Endpoint, Instant};
//! use rand_chacha::ChaCha20Rng;
//! use rand_core::SeedableRng;
//!
//! // Seed from the OS in real use; a fixed seed keeps this example deterministic.
//! let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(1));
//! let now = Instant::from_nanos(0);
//! let local = "10.0.9.2".parse().unwrap();
//! let remote = "10.0.1.2:5201".parse().unwrap();
//! let _h = ep.connect_mptcp(now, local, remote, ConnectConfig::default()).unwrap();
//!
//! let mut buf = [0u8; 1500];
//! let n = ep.poll_transmit(now, &mut buf).expect("the SYN");
//! // Send `&buf[..n]` on the network, then feed replies to `ep.handle_packet(now, ..)`.
//! assert!(n > 0);
//! ```

#![forbid(unsafe_code)]

mod connection;
pub mod crypto;
mod endpoint;
mod mptcp;
mod seq;
pub mod tcp;
mod time;
pub mod wire;

pub use connection::{Connection, ReadError, WriteError};
pub use endpoint::{
    AddSubflowError, AddressError, ConnectError, ConnectionHandle, Endpoint, Event, ListenConfig,
    ListenError, MpTcpRst, SubflowError,
};
#[doc(hidden)]
pub use mptcp::DebugStats;
pub use mptcp::SubflowId;
pub use seq::SeqNum;
pub use tcp::{CloseReason, CongestionControlKind, ConnectConfig};
pub use time::Instant;
