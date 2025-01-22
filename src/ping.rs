use crate::args;
use crate::icmp::{IcmpType, Ipv4Packet};
use crate::packet::Packet;
use libc::{cmsghdr, CMSG_DATA};
use socket2::{Domain, MaybeUninitSlice, MsgHdrMut, Protocol, Socket, Type};
use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::thread::sleep;
use std::time::{Duration, Instant};
use zerocopy::FromBytes;

pub fn send_ping(args: &args::Args) -> io::Result<()> {
    let target_ip = get_target_ip(&args.destination);
    let target_addr = SocketAddr::new(target_ip, 0);
    let socket = match args.ipv6 {
        true => Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)),
        false => Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)),
    }?;
    let mut packet = match args.ipv6 {
        true => Packet::new(IcmpType::V6, args.payload_len),
        false => Packet::new(IcmpType::V4, args.payload_len),
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

fn get_target_ip(destination: &String) -> IpAddr {
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
