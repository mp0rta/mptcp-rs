//! Address ids (M3 spec §3.3, §4.1): our IP-to-id bindings and the peer's announced addresses.
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

/// Our local IPs, indexed by address id, each with whether the peer has learned its id. A
/// binding lasts for the connection's life; an id is reused only for the same IP (RFC 8684
/// L2043–2051).
pub(crate) struct LocalAddrs(Vec<(IpAddr, bool)>);

impl LocalAddrs {
    /// The initial local IP is id 0, which the peer knows from the MP_CAPABLE handshake.
    pub fn new(initial: IpAddr) -> Self {
        Self(vec![(initial, true)])
    }
    pub fn id(&self, ip: IpAddr) -> Option<u8> {
        (self.0.iter().position(|a| a.0 == ip)).map(|i| i as u8)
    }
    /// `ip`'s id, binding the next one to a new IP; `None` once 256 IPs are bound.
    pub fn bind(&mut self, ip: IpAddr) -> Option<u8> {
        self.id(ip).or_else(|| {
            let id = u8::try_from(self.0.len()).ok()?;
            self.0.push((ip, false));
            Some(id)
        })
    }
    /// An MP_JOIN SYN carrying `id` went out.
    pub fn sent(&mut self, id: u8) {
        self.0[usize::from(id)].1 = true;
    }
    /// The peer has learned `id`: it may be named in a REMOVE_ADDR.
    pub fn on_wire(&self, id: u8) -> bool {
        self.0[usize::from(id)].1
    }
}

/// One entry of the peer address table, keyed by the peer's address id.
// Built from an authenticated ADD_ADDR (M3 Task 9).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct PeerAddr {
    /// Set only from an authenticated ADD_ADDR.
    pub advertised: Option<(IpAddr, u16)>,
    /// A join to the advertised endpoint failed: no new join to it until a refresh.
    pub failed: bool,
}

/// The peer's announced addresses (soft state, RFC 8684 L1999–2005).
#[derive(Default)]
pub(crate) struct PeerAddrs(pub BTreeMap<u8, PeerAddr>);

impl PeerAddrs {
    /// `remote` is an announced endpoint marked failed.
    pub fn failed(&self, remote: SocketAddr) -> bool {
        let r = Some((remote.ip(), remote.port()));
        self.0.values().any(|a| a.failed && a.advertised == r)
    }
}
