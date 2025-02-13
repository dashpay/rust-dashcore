use std::io;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::consensus::{Decodable, Encodable, encode};

impl Encodable for SocketAddr {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let ip_address = match self.ip() {
            IpAddr::V4(v4) => {
                // Create a 16-byte array for the IP address.
                let mut ip_address = [0u8; 16];
                // For IPv4, the previous implementation stored the IPv4 address in the last 4 bytes.
                ip_address[12..16].copy_from_slice(&v4.octets());
                ip_address
            }
            IpAddr::V6(_) => unimplemented!("ipv6 not supported"),
        };

        let mut len = 0;

        // Encode the 16-byte IP address.
        len += ip_address.consensus_encode(writer)?;
        // Encode the port: the legacy code swaps the port’s bytes before encoding.
        len += self.port().swap_bytes().consensus_encode(writer)?;

        Ok(len)
    }
}

impl Decodable for SocketAddr {
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, encode::Error> {
        // Decode the 16-byte IP address.
        let ip_address: [u8; 16] = Decodable::consensus_decode(reader)?;
        // Decode the port (which was stored in swapped order).
        let port: u16 = Decodable::consensus_decode(reader)?;
        // Swap the port bytes back to native order.
        let port = port.swap_bytes();
        // Extract the IPv4 octets from the last 4 bytes.
        let ipv4_octets: [u8; 4] = ip_address[12..16]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid IPv4 address"))?;

        let ip = IpAddr::V4(Ipv4Addr::from(ipv4_octets));

        Ok(SocketAddr::new(ip, port))
    }
}
