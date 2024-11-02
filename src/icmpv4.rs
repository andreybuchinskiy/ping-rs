use zerocopy::byteorder::network_endian;
use zerocopy::IntoBytes;
use zerocopy_derive::{FromBytes, Immutable, IntoBytes, KnownLayout};
#[derive(IntoBytes, KnownLayout, Immutable, Debug)]
#[repr(C)]
pub(crate) struct IcmpEchoRequest {
    icmp_type: u8,
    icmp_code: u8,
    checksum: network_endian::U16,
    identifier: network_endian::U16,
    sequence_number: network_endian::U16,
}

impl IcmpEchoRequest {
    pub fn new() -> Self {
        let mut packet = Self {
            icmp_type: 8,
            icmp_code: 0,
            checksum: 0.into(),
            identifier: 0.into(),
            sequence_number: 0.into(),
        };
        packet.calculate_checksum();
        packet
    }

    pub fn calculate_checksum(&mut self) {
        self.checksum = 0.into();
        let mut sum: u32 = 0;

        for i in (0..self.as_bytes().len()).step_by(2) {
            let word = u16::from_be_bytes([
                self.as_bytes()[i],
                *self.as_bytes().get(i + 1).unwrap_or(&0),
            ]);
            sum = sum.wrapping_add(word as u32);
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        let checksum = !(sum as u16);
        self.checksum = network_endian::U16::from(checksum);
    }

    pub(crate) fn increment_sequence(&mut self) {
        self.sequence_number += 1;
        self.calculate_checksum();
    }
}
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C)]
pub(crate) struct Ipv4Packet {
    pub(crate) ver_len_tos: network_endian::U16,
    pub(crate) total_len: network_endian::U16,
    pub(crate) identification: network_endian::U16,
    pub(crate) flags_frag_offset: network_endian::U16,
    pub(crate) ttl: u8,
    pub(crate) protocol: u8,
    pub(crate) checksum: network_endian::U16,
    pub(crate) source_address: network_endian::U32,
    pub(crate) destination_address: network_endian::U32,
    pub(crate) icmp_header: IcmpEchoReply,
}

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C)]
pub(crate) struct IcmpEchoReply {
    pub(crate) icmp_type: u8,
    pub(crate) icmp_code: u8,
    pub(crate) checksum: network_endian::U16,
    pub(crate) identifier: network_endian::U16,
    pub(crate) sequence_number: network_endian::U16,
}
