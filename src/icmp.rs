use zerocopy::byteorder::network_endian;
use zerocopy_derive::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[repr(u8)]
pub enum IcmpType {
    V4 = 8,
    V6 = 128,
}

#[repr(C)]
#[derive(IntoBytes, KnownLayout, Immutable, Debug)]
pub struct IcmpEchoRequest {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub checksum: network_endian::U16,
    pub identifier: network_endian::U16,
    pub sequence_number: network_endian::U16,
}

impl IcmpEchoRequest {
    pub fn new(icmp_type: IcmpType) -> IcmpEchoRequest {
        IcmpEchoRequest {
            icmp_type: icmp_type as u8,
            icmp_code: 0,
            checksum: 0.into(),
            identifier: 0.into(),
            sequence_number: 0.into(),
        }
    }
}

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C)]
pub struct Ipv4Packet {
    pub ver_len_tos: network_endian::U16,
    pub total_len: network_endian::U16,
    pub identification: network_endian::U16,
    pub flags_frag_offset: network_endian::U16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: network_endian::U16,
    pub source_address: network_endian::U32,
    pub destination_address: network_endian::U32,
}
