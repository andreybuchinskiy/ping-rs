use clap::Parser;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::mem::MaybeUninit;
use std::net::ToSocketAddrs;
use std::net::{IpAddr, SocketAddr};
use std::thread::sleep;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
struct Args {
    // #[arg(short, long)]
    destination: String,
    // #[arg(short, optional)]
    // count: u16,
    #[arg(short, default_value_t = 1.)]
    interval: f64,
}

fn create_icmp_echo_request(sequence_number: u16) -> Vec<u8> {
    let mut packet = vec![0u8; 8];

    packet[0] = 8;
    packet[1] = 0;

    packet[2] = 0;
    packet[3] = 0;

    packet[4] = (sequence_number >> 8) as u8;
    packet[5] = (sequence_number & 0xFF) as u8;

    packet[6] = (sequence_number >> 8) as u8;
    packet[7] = (sequence_number & 0xFF) as u8;
    let checksum: u16 = calculate_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = (checksum & 0xFF) as u8;
    packet
}

fn calculate_checksum(packet: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for i in (0..packet.len()).step_by(2) {
        let word = u16::from_be_bytes([packet[i], *packet.get(i + 1).unwrap_or(&0)]);
        sum = sum.wrapping_add(word as u32);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
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
    // match socket.set_header_included(true) {
    //     Ok(_) => (),
    //     Err(e) => panic!("Failed to set header included: {}", e),
    // }

    let target_addr = SocketAddr::new(target_ip, 0);

    println!("PING {} ({}) 0(28) bytes of data.", target_ip, target_ip);
    let mut sequence_number = 1;
    let interval = Duration::from_secs_f64(args.interval);
    loop {
        let packet = create_icmp_echo_request(sequence_number);

        let sent_time = Instant::now();
        socket.send_to(&packet, &target_addr.into())?;

        let mut buffer = [MaybeUninit::<u8>::uninit(); 1024];

        match socket.recv_from(&mut buffer) {
            Ok((n, addr)) => {
                let recv_time = Instant::now();
                let rtt = recv_time - sent_time;
                let ttl = unsafe { buffer[8].assume_init() };
                println!(
                    "{} bytes from {}: icmp_seq={} ttl={} time={:.3} ms",
                    n,
                    addr.as_socket().unwrap().ip(),
                    sequence_number,
                    ttl,
                    rtt.as_secs_f64() * 1000.0
                );
            }
            Err(e) => {
                println!("Failed to receive ICMP Echo Reply: {}", e);
            }
        }
        sequence_number += 1;
        sleep(interval);
    }
}
