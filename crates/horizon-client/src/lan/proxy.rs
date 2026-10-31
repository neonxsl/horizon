//! PROXY protocol v2 in front of a dedicated server (frp's
//! `transport.proxyProtocolVersion = "v2"`, HAProxy, playit): the tunnel
//! connects from a trusted address and starts with a binary header naming
//! the player's own address, which the server then uses for bans, sessions
//! and logs. Off unless `horizon-proxy-protocol=true`. While it's on,
//! connections from `horizon-proxy-direct` (a LAN, say) come in without a
//! header, and any other one is closed before the handshake.
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub const PROPERTY: &str = "horizon-proxy-protocol";
pub const TRUSTED_PROPERTY: &str = "horizon-proxy-trusted";
pub const DIRECT_PROPERTY: &str = "horizon-proxy-direct";

const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";

/// An address, or a range of them (`192.168.1.0/24`, `fd00::/8`).
#[derive(Clone, Debug, PartialEq)]
pub struct Range {
    base: IpAddr,
    bits: u8,
}

impl Range {
    pub fn parse(text: &str) -> Result<Range, String> {
        let (ip, bits) = match text.trim().split_once('/') {
            Some((ip, bits)) => (ip, Some(bits)),
            None => (text.trim(), None),
        };
        let base: IpAddr = ip
            .parse()
            .map_err(|_| format!("{text:?} is not an address"))?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        let bits = match bits {
            Some(b) => b
                .parse::<u8>()
                .ok()
                .filter(|b| *b <= max)
                .ok_or_else(|| format!("{text:?}: the range is /0 to /{max}"))?,
            None => max,
        };
        Ok(Range { base, bits })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            v4 => v4,
        };
        match (self.base, ip) {
            (IpAddr::V4(b), IpAddr::V4(i)) => {
                let mask = u32::MAX.checked_shl(32 - self.bits as u32).unwrap_or(0);
                u32::from(b) & mask == u32::from(i) & mask
            }
            (IpAddr::V6(b), IpAddr::V6(i)) => {
                let mask = u128::MAX.checked_shl(128 - self.bits as u32).unwrap_or(0);
                u128::from(b) & mask == u128::from(i) & mask
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for Range {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.base, self.bits)
    }
}

pub fn ranges(text: &str) -> Result<Vec<Range>, String> {
    text.split(',')
        .filter(|s| !s.trim().is_empty())
        .map(Range::parse)
        .collect()
}

/// The server's PROXY protocol settings; `/proxy on|off` switches it while
/// the server runs.
pub struct Proxy {
    pub on: AtomicBool,
    /// Where the tunnel connects from (its header is believed).
    pub trusted: Vec<Range>,
    /// Who may connect without a header.
    pub direct: Vec<Range>,
}

/// What to do with a new connection.
#[derive(Debug, PartialEq)]
pub enum Verdict {
    /// The player's address (the header's, or the connection's own).
    Accept(SocketAddr),
    Refuse(String),
}

impl Proxy {
    pub fn from_properties(
        raw: &std::collections::HashMap<String, String>,
    ) -> Result<Self, String> {
        let get = |k: &str| raw.get(k).map(String::as_str).unwrap_or("");
        let trusted = match get(TRUSTED_PROPERTY).trim() {
            "" => ranges("127.0.0.1,::1")?,
            text => ranges(text)?,
        };
        Ok(Proxy {
            on: AtomicBool::new(get(PROPERTY).trim().eq_ignore_ascii_case("true")),
            trusted,
            direct: ranges(get(DIRECT_PROPERTY))?,
        })
    }

    pub fn is_on(&self) -> bool {
        self.on.load(Ordering::Relaxed)
    }

    /// Reads the header from a trusted connection; lets a direct one through.
    pub fn admit(&self, stream: &mut TcpStream, peer: SocketAddr) -> Verdict {
        if !self.is_on() {
            return Verdict::Accept(peer);
        }
        if self.trusted.iter().any(|r| r.contains(peer.ip())) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let header = read_header(stream, peer);
            let _ = stream.set_read_timeout(None);
            return match header {
                Ok(addr) => Verdict::Accept(addr),
                Err(e) => Verdict::Refuse(format!("bad PROXY header from {peer}: {e}")),
            };
        }
        if self.direct.iter().any(|r| r.contains(peer.ip())) {
            return Verdict::Accept(peer);
        }
        Verdict::Refuse(format!("{peer} is neither the proxy nor allowed directly"))
    }
}

/// A PROXY protocol v2 header: the source address (`PROXY` over TCP), or the
/// connection's own for `LOCAL` (the proxy's health checks).
pub fn read_header(stream: &mut impl Read, peer: SocketAddr) -> Result<SocketAddr, String> {
    let mut fixed = [0u8; 16];
    stream.read_exact(&mut fixed).map_err(|e| e.to_string())?;
    if fixed[..12] != SIGNATURE {
        return Err("no v2 signature".into());
    }
    let (version, command) = (fixed[12] >> 4, fixed[12] & 0x0F);
    if version != 2 {
        return Err(format!("version {version}"));
    }
    let len = u16::from_be_bytes([fixed[14], fixed[15]]) as usize;
    let mut rest = vec![0u8; len];
    stream.read_exact(&mut rest).map_err(|e| e.to_string())?;
    match (command, fixed[13]) {
        (0, _) => Ok(peer),
        // TCP over IPv4: source, destination, source port, destination port.
        (1, 0x11) if len >= 12 => Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3])),
            u16::from_be_bytes([rest[8], rest[9]]),
        )),
        (1, 0x21) if len >= 36 => {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&rest[..16]);
            Ok(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(ip)),
                u16::from_be_bytes([rest[32], rest[33]]),
            ))
        }
        (1, family) => Err(format!("address family {family:#x}")),
        (c, _) => Err(format!("command {c}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(command: u8, family: u8, body: &[u8]) -> Vec<u8> {
        let mut h = SIGNATURE.to_vec();
        h.push(0x20 | command);
        h.push(family);
        h.extend((body.len() as u16).to_be_bytes());
        h.extend(body);
        h
    }

    #[test]
    fn ipv4_and_ipv6_sources_and_local() {
        let peer: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let v4 = header(
            1,
            0x11,
            &[203, 0, 113, 7, 10, 0, 0, 1, 0x30, 0x39, 0x63, 0xDD],
        );
        assert_eq!(
            read_header(&mut &v4[..], peer),
            Ok("203.0.113.7:12345".parse().unwrap())
        );
        let mut body = vec![0u8; 36];
        body[0] = 0x20;
        body[1] = 0x01;
        body[15] = 5;
        body[32] = 0x01;
        body[33] = 0xBB;
        let v6 = header(1, 0x21, &body);
        assert_eq!(
            read_header(&mut &v6[..], peer),
            Ok("[2001::5]:443".parse().unwrap())
        );
        let local = header(0, 0, &[]);
        assert_eq!(read_header(&mut &local[..], peer), Ok(peer));
        assert!(read_header(&mut &b"GET / HTTP/1.1\r\n"[..], peer).is_err());
    }

    #[test]
    fn ranges_match_their_addresses() {
        let lan = Range::parse("192.168.1.0/24").unwrap();
        assert!(lan.contains("192.168.1.108".parse().unwrap()));
        assert!(!lan.contains("192.168.2.1".parse().unwrap()));
        assert!(lan.contains("::ffff:192.168.1.5".parse().unwrap()));
        assert!(
            Range::parse("10.0.0.1")
                .unwrap()
                .contains("10.0.0.1".parse().unwrap())
        );
        assert!(
            Range::parse("fd00::/8")
                .unwrap()
                .contains("fd12::1".parse().unwrap())
        );
        assert!(Range::parse("10.0.0.0/33").is_err());
    }
}
