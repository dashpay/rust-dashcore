use std::io;
use std::io::Write;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::consensus::{Decodable, Encodable, encode};

impl Encodable for SocketAddr {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let ip = match self.ip() {
            IpAddr::V4(v4) => {
                // For IPv4, the previous implementation stored the IPv4 address in the last 4 bytes.
                v4.to_ipv6_mapped().to_bits()
            }
            IpAddr::V6(v6) => v6.to_bits(),
        };

        let mut len = 0;

        // Encode the 16-byte IP address.
        len += ip.consensus_encode(writer)?;

        // Encode the port: the legacy code swaps the port’s bytes before encoding.
        len += self.port().swap_bytes().consensus_encode(writer)?;

        Ok(len)
    }
}

impl Decodable for SocketAddr {
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, encode::Error> {
        // Decode the 16-byte IP address.
        let ip = u128::consensus_decode(reader)?;

        // Decode the port (which was stored in swapped order).
        let port = u16::consensus_decode(reader)?.swap_bytes();

        let ipv6 = Ipv6Addr::from(ip);

        if let Some(ipv4) = ipv6.to_ipv4() {
            Ok(SocketAddr::V4(SocketAddrV4::new(ipv4, port)))
        } else {
            Ok(SocketAddr::V6(SocketAddrV6::new(ipv6, port, 0, 0)))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn encode_decode_ipv4() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let address = SocketAddr::V4(SocketAddrV4::new(ip, 1234));
        let mut writer = Vec::new();
        address.consensus_encode(&mut writer).unwrap();

        let mut reader = &writer[..];
        let decoded = SocketAddr::consensus_decode(&mut reader).unwrap();

        assert_eq!(address, decoded);
    }

    #[test]
    fn encode_decode_ipv4_mapped() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let address = SocketAddr::V6(SocketAddrV6::new(ip.to_ipv6_mapped(), 1234, 0, 0));
        let mut writer = Vec::new();
        address.consensus_encode(&mut writer).unwrap();

        let mut reader = &writer[..];
        let decoded = SocketAddr::consensus_decode(&mut reader).unwrap();

        assert!(decoded.is_ipv4());
        assert_eq!(decoded.ip(), IpAddr::V4(ip));

        let mut decoded_writer = Vec::new();
        decoded.consensus_encode(&mut decoded_writer).unwrap();

        assert_eq!(writer, decoded_writer);
    }

    #[test]
    fn encode_decode_ipv6() {
        let address = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0, 10, 20, 30, 40, 50, 60, 70),
            1234,
            0,
            0,
        ));
        let mut writer = Vec::new();
        address.consensus_encode(&mut writer).unwrap();
        let mut reader = &writer[..];
        let decoded = SocketAddr::consensus_decode(&mut reader).unwrap();

        assert_eq!(address, decoded);
    }
}
