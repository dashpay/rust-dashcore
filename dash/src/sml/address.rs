use std::io;
use std::io::Write;
use std::net::Ipv4Addr;
use crate::consensus::{encode, Decodable, Encodable};

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub struct ServiceAddress {
    pub ip: Ipv4Addr,
    pub port: u16,
}


impl Encodable for ServiceAddress {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        // Create a 16-byte array for the IP address.
        // For IPv4, the previous implementation stored the IPv4 address in the last 4 bytes.
        let mut ip_address = [0u8; 16];
        ip_address[12..16].copy_from_slice(&self.ip.octets());

        let mut len = 0;
        // Encode the 16-byte IP address.
        len += ip_address.consensus_encode(writer)?;
        // Encode the port: the legacy code swaps the port’s bytes before encoding.
        len += self.port.swap_bytes().consensus_encode(writer)?;
        Ok(len)
    }
}

impl Decodable for ServiceAddress {
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
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid IPv4 address"))?;
        let ip = Ipv4Addr::from(ipv4_octets);
        Ok(ServiceAddress { ip, port })
    }
}