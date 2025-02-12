use std::net::Ipv4Addr;
use crate::internal_macros::impl_consensus_encoding;

pub struct ServiceAddress {
    pub ip: Ipv4Addr,
    pub port: u16,
}

impl_consensus_encoding!(ServiceAddress, ip, port);