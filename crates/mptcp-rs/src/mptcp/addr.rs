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
pub(crate) struct PeerAddr {
    /// Set only from an authenticated ADD_ADDR.
    pub advertised: Option<(IpAddr, u16)>,
    /// A join to the advertised endpoint failed: no new join to it until a refresh.
    pub failed: bool,
}

/// Entries of the peer address table (M3 spec §3.3).
const PEER_ADDR_CAP: usize = 8;

/// The peer's announced addresses (soft state, RFC 8684 L1999–2005).
#[derive(Default)]
pub(crate) struct PeerAddrs(pub BTreeMap<u8, PeerAddr>);

impl PeerAddrs {
    /// Binds `id` to `addr`: a new entry, or a refresh that may change the port and clears the
    /// failed mark. False, changing nothing, when the table is full.
    pub fn announce(&mut self, id: u8, addr: SocketAddr) -> bool {
        if !self.0.contains_key(&id) && self.0.len() >= PEER_ADDR_CAP {
            return false;
        }
        let advertised = Some((addr.ip(), addr.port()));
        let entry = PeerAddr {
            advertised,
            failed: false,
        };
        self.0.insert(id, entry);
        true
    }
    /// A join to `remote` failed: if announced, no new join goes to it until a refresh (RFC
    /// 8684 L2036–2039).
    pub fn fail(&mut self, remote: SocketAddr) {
        let r = Some((remote.ip(), remote.port()));
        for a in self.0.values_mut().filter(|a| a.advertised == r) {
            a.failed = true;
        }
    }
    /// `remote` is an announced endpoint marked failed.
    pub fn failed(&self, remote: SocketAddr) -> bool {
        let r = Some((remote.ip(), remote.port()));
        self.0.values().any(|a| a.failed && a.advertised == r)
    }
}
