use crate::network::address::{AddrV2, AddrV2Message};
use crate::network::constants::ServiceFlags;
use std::net::Ipv4Addr;

impl AddrV2Message {
    pub fn dummy(time: u32, addr: Ipv4Addr, port: u16) -> Self {
        Self {
            time,
            services: ServiceFlags::NONE,
            addr: AddrV2::Ipv4(addr),
            port,
        }
    }
}
