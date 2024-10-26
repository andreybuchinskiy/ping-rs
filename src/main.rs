#![feature(maybe_uninit_array_assume_init)]
use clap::Parser;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::mem::MaybeUninit;
use std::net::ToSocketAddrs;
use std::net::{IpAddr, SocketAddr};
use std::thread::sleep;
use std::time::{Duration, Instant};
use zerocopy::byteorder::network_endian;
use zerocopy::{FromBytes, IntoBytes};
use zerocopy_derive::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(Parser, Debug)]
struct Args {
    // #[arg(short, long)]
    destination: String,
    // #[arg(short, optional)]
    // count: u16,
    #[arg(short, default_value_t = 1.)]
    interval: f64,
}

#[derive(IntoBytes, KnownLayout, Immutable, Debug)]
#[repr(C)]
struct IcmpEchoRequest {
    icmp_type: u8,
    icmp_code: u8,
    checksum: network_endian::U16,
    identifier: network_endian::U16,
    sequence_number: network_endian::U16,
}

#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C)]
struct Ipv4Packet {
    ver_len_tos: network_endian::U16,
    total_len: network_endian::U16,
    identification: network_endian::U16,
    flags_frag_offset: network_endian::U16,
    ttl: u8,
    protocol: u8,
    checksum: network_endian::U16,
    source_address: network_endian::U32,
    destination_address: network_endian::U32,
}

impl IcmpEchoRequest {
    fn new(icmp_type: u8, icmp_code: u8, identifier: network_endian::U16) -> Self {
        let mut packet = Self {
            icmp_type,
            icmp_code,
            checksum: 0.into(),
            identifier,
            sequence_number: 0.into(),
        };
        packet.calculate_checksum();
        packet
    }

    fn calculate_checksum(&mut self) {
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

    fn increment_sequence(&mut self) {
        self.sequence_number += 1;
        self.calculate_checksum();
    }
}

fn get_target_ip(destination: String) -> IpAddr {
    let target_ip: IpAddr = match destination.parse() {
        Ok(target_ip) => target_ip,
        Err(_) => {
            let target_ip: IpAddr = match format!("{}:0", destination).to_socket_addrs() {
                Ok(mut target_ip) => target_ip.next().unwrap().ip(),
                Err(e) => panic!("Unable to get IP address for {}: {}", destination, e),
            };
            target_ip
        }
    };
    target_ip
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    let target_ip = get_target_ip(args.destination);
    let socket = match target_ip {
        IpAddr::V4(_) => Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)),
        IpAddr::V6(_) => Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)),
    }?;

    socket.set_read_timeout(Some(Duration::from_secs(3)))?;

    let target_addr = SocketAddr::new(target_ip, 0);

    let mut packet = IcmpEchoRequest::new(8, 0, 0.into());
    println!(
        "PING {} ({}) 0({}) bytes of data.",
        target_ip,
        target_ip,
        packet.as_bytes().len()
    );
    let interval = Duration::from_secs_f64(args.interval);
    loop {
        let sent_time = Instant::now();
        socket.send_to(packet.as_bytes(), &target_addr.into())?;

        let mut buffer = [MaybeUninit::<u8>::uninit(); 1024];

        match socket.recv_from(&mut buffer) {
            Ok((n, addr)) => {
                let recv_time = Instant::now();
                let rtt = recv_time - sent_time;
                let init_buffer = unsafe { &MaybeUninit::array_assume_init(buffer) };
                let res = Ipv4Packet::ref_from_bytes(&init_buffer[0..20]).unwrap();
                println!(
                    "{} bytes from {}: icmp_seq={} ttl={} time={:.3} ms",
                    n,
                    addr.as_socket().unwrap().ip(),
                    packet.sequence_number,
                    res.ttl,
                    rtt.as_secs_f64() * 1000.0
                );
                packet.increment_sequence();
            }
            Err(e) => {
                println!("Failed to receive ICMP Echo Reply: {}", e);
            }
        }
        sleep(interval);
    }
}
