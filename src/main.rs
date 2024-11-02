#![feature(maybe_uninit_array_assume_init)]
#![feature(maybe_uninit_slice)]

mod args;
mod icmpv4;

use crate::args::Args;
use clap::Parser;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::mem::MaybeUninit;
use std::net::ToSocketAddrs;
use std::net::{IpAddr, SocketAddr};
use std::thread::sleep;
use std::time::{Duration, Instant};
use zerocopy::{FromBytes, IntoBytes};

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

    let mut packet = icmpv4::IcmpEchoRequest::new();
    println!(
        "PING {} ({}) 0({}) bytes of data.",
        target_ip,
        target_ip,
        packet.as_bytes().len() + 20
    );
    let interval = Duration::from_secs_f64(args.interval);
    loop {
        let mut buffer = [MaybeUninit::<u8>::uninit(); 1024];
        let sent_time = Instant::now();
        socket.send_to(packet.as_bytes(), &target_addr.into())?;
        match socket.recv_from(&mut buffer) {
            Ok((n, addr)) => {
                let recv_time = Instant::now();
                let rtt = recv_time - sent_time;
                let init_buffer = unsafe { &MaybeUninit::slice_assume_init_ref(&buffer[0..n]) };
                let res = match icmpv4::Ipv4Packet::ref_from_bytes(&init_buffer[0..n]) {
                    Ok(res) => res,
                    Err(e) => panic!("Failed to parse IPv4 packet: {}", e),
                };
                println!(
                    "{} bytes from {}: icmp_seq={} ttl={} time={:.3} ms",
                    n,
                    addr.as_socket().unwrap().ip(),
                    res.icmp_header.sequence_number,
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
