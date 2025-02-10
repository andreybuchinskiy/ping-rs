use crate::args;
use crate::dns::{dns_query, QueryType};
use crate::icmp::{IcmpType, Ipv4Packet};
use crate::packet::Packet;
use libc::{cmsghdr, CMSG_DATA};
use socket2::{Domain, MaybeUninitSlice, MsgHdrMut, Protocol, Socket, Type};
use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::thread::sleep;
use std::time::{Duration, Instant};
use zerocopy::FromBytes;

pub fn send_ping(args: &args::Args) -> io::Result<()> {
    let target_ip = get_target_ip(&args.destination, args.ipv6)?;
    let target_addr = SocketAddr::new(target_ip, 0);
    let (socket, mut packet) = match target_ip {
        IpAddr::V6(_) => (
            Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?,
            Packet::new(IcmpType::V6, args.payload_len),
        ),
        IpAddr::V4(_) => (
            Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?,
            Packet::new(IcmpType::V4, args.payload_len),
        ),
    };
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    if args.ipv6 {
        socket.set_recv_hoplimit_v6(true)?;
    }
    let interval = Duration::from_secs_f64(args.interval);
    match args.count {
        Some(count) => {
            for _ in 0..count {
                ping(&socket, &mut packet, target_addr)?;
                sleep(interval);
                packet.increment_sequence();
            }
            Ok(())
        }
        None => loop {
            ping(&socket, &mut packet, target_addr)?;
            sleep(interval);
            packet.increment_sequence();
        },
    }
}

fn ping(socket: &Socket, packet: &mut Packet, target_addr: SocketAddr) -> io::Result<()> {
    let msg = MsgHdrMut::new();
    let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
    let mut buffer = [MaybeUninitSlice::new(&mut buf)];
    let mut cbuf = [MaybeUninit::<u8>::uninit(); 1024];
    let msg = msg.with_buffers(&mut buffer);
    let mut msg = msg.with_control(&mut cbuf);
    let sent_time = Instant::now();
    socket.send_to(&packet.to_bytes(), &target_addr.into())?;
    match socket.recvmsg(&mut msg, 0) {
        Ok(len) => {
            let recv_time = Instant::now();
            let rtt = recv_time - sent_time;
            let ttl = match target_addr {
                SocketAddr::V4(_) => {
                    let init_buffer = unsafe { &MaybeUninit::slice_assume_init_ref(&buf[0..len]) };
                    let packet = match Ipv4Packet::ref_from_bytes(&init_buffer[0..20]) {
                        Ok(res) => res,
                        Err(e) => panic!("Failed to parse IPv4 packet: {}", e),
                    };
                    packet.ttl
                }
                SocketAddr::V6(_) => {
                    let cbuf_len = msg.control_len();
                    let init_cbuf =
                        unsafe { &MaybeUninit::slice_assume_init_ref(&cbuf[0..cbuf_len]) };
                    unsafe { *CMSG_DATA(init_cbuf.as_ptr() as *mut cmsghdr) }
                }
            };
            println!(
                "{} bytes from {}: icmp_seq={} ttl={} time={:.3} ms",
                len,
                target_addr.ip(),
                packet.header.sequence_number,
                ttl,
                rtt.as_secs_f64() * 1000.0
            );
        }
        Err(e) => println!("Failed to receive ICMP Echo Reply: {}", e),
    }
    Ok(())
}

fn get_target_ip(destination: &str, ipv6: bool) -> io::Result<IpAddr> {
    let target_ip: IpAddr = match destination.parse() {
        Ok(target_ip) => target_ip,
        Err(_) => {
            let res = match ipv6 {
                false => dns_query(destination, QueryType::A)?,
                true => dns_query(destination, QueryType::Aaaa)?,
            };

            match res.answers.first().unwrap().answer {
                crate::dns::Answer::Ipv4(x) => std::net::IpAddr::V4(x),
                crate::dns::Answer::Ipv6(x) => std::net::IpAddr::V6(x),
                _ => panic!("Failed to get an IP address"),
            }
        }
    };
    Ok(target_ip)
}
