use crate::icmp::{IcmpEchoRequest, IcmpType};
use rand::{thread_rng, Rng};
use zerocopy::byteorder::network_endian;
use zerocopy::IntoBytes;

#[derive(Debug)]
pub struct Packet {
    pub header: IcmpEchoRequest,
    payload: Vec<u8>,
}

impl Packet {
    pub fn new(icmp_type: IcmpType, payload_len: u16) -> Packet {
        let mut rng = thread_rng();
        let payload = (0..payload_len).map(|_| rng.gen()).collect();
        let header = IcmpEchoRequest::new(icmp_type);
        let mut packet = Packet { header, payload };
        packet.calculate_checksum();
        packet
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = self.header.as_bytes().to_vec();
        buffer.extend_from_slice(&self.payload);
        buffer
    }

    pub fn calculate_checksum(&mut self) {
        self.header.checksum = 0.into();
        let mut sum: u32 = 0;

        for i in (0..self.to_bytes().len()).step_by(2) {
            let word = u16::from_be_bytes([
                self.to_bytes()[i],
                *self.to_bytes().get(i + 1).unwrap_or(&0),
            ]);
            sum = sum.wrapping_add(word as u32);
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        let checksum = !(sum as u16);
        self.header.checksum = network_endian::U16::from(checksum);
    }

    pub fn increment_sequence(&mut self) {
        self.header.sequence_number += 1;
        self.calculate_checksum();
    }
}
