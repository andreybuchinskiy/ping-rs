use rand::Rng;
use std::fs;
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use zerocopy::byteorder::U16;
use zerocopy::TryFromBytes;
use zerocopy::{BigEndian, IntoBytes};
use zerocopy_derive::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[repr(u16)]
#[derive(Debug, Clone, Copy, IntoBytes, Immutable)]
pub enum QueryType {
    A = 1,
    Ns = 2,
    Aaaa = 28,
    Ptr = 12,
}

impl QueryType {
    pub fn from_u16(value: u16) -> Option<QueryType> {
        match value {
            1 => Some(QueryType::A),
            2 => Some(QueryType::Ns),
            28 => Some(QueryType::Aaaa),
            12 => Some(QueryType::Ptr),
            _ => None,
        }
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, IntoBytes, Immutable)]
enum QueryClass {
    In = 1,
}

impl QueryClass {
    fn from_u16(value: u16) -> Option<QueryClass> {
        match value {
            1 => Some(QueryClass::In),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout)]
struct DnsHeader {
    id: U16<BigEndian>,
    flags: U16<BigEndian>,
    questions: U16<BigEndian>,
    answer_rr: U16<BigEndian>,
    authority_rr: U16<BigEndian>,
    additional_rr: U16<BigEndian>,
}

impl DnsHeader {
    fn new_query() -> DnsHeader {
        let id = rand::thread_rng().gen_range(0..=u16::MAX);
        DnsHeader {
            id: id.into(),
            flags: 0x0100.into(),
            questions: 1.into(),
            answer_rr: 0.into(),
            authority_rr: 0.into(),
            additional_rr: 0.into(),
        }
    }
}

#[repr(C)]
#[derive(Debug)]
struct DnsQuery {
    header: DnsHeader,
    queries: Vec<DnsQuestion>,
}

impl DnsQuery {
    pub fn new_query(lookup: &str, qtype: QueryType) -> DnsQuery {
        let header = DnsHeader::new_query();
        let mut queries = Vec::new();
        let question = DnsQuestion::new(lookup, qtype);
        queries.push(question);
        DnsQuery { header, queries }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(self.header.as_bytes());
        buffer.extend(self.queries.iter().flat_map(|x| x.to_bytes()));
        buffer
    }
}

#[repr(C)]
#[derive(Debug)]
struct DnsQuestion {
    query: Vec<u8>,
    qtype: QueryType,
    qclass: QueryClass,
}

impl DnsQuestion {
    fn new(lookup: &str, qtype: QueryType) -> DnsQuestion {
        let query = Self::encode_domain_name(lookup);
        DnsQuestion {
            query,
            qtype,
            qclass: QueryClass::In,
        }
    }

    fn from_bytes(buffer: &[u8], offset: &usize, null_byte_pos: usize) -> DnsQuestion {
        let end = null_byte_pos + 1;
        let query = &buffer[*offset..end];
        let qtype =
            QueryType::from_u16(u16::from_be_bytes([buffer[end], buffer[end + 1]])).unwrap();
        let qclass =
            QueryClass::from_u16(u16::from_be_bytes([buffer[end + 2], buffer[end + 3]])).unwrap();
        DnsQuestion {
            query: query.into(),
            qtype,
            qclass,
        }
    }

    fn encode_domain_name(domain: &str) -> Vec<u8> {
        let mut encoded = Vec::new();
        for part in domain.split(".") {
            encoded.push(part.len() as u8);
            encoded.extend_from_slice(part.as_bytes());
        }
        encoded.push(0);
        encoded
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.query);
        buffer.extend_from_slice(&(self.qtype as u16).to_be_bytes());
        buffer.extend_from_slice(&(self.qclass as u16).to_be_bytes());
        buffer
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct DnsResponse {
    header: DnsHeader,
    questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
    authority_rr: Vec<DnsAnswer>,
    additional_rr: Vec<DnsAnswer>,
}

impl DnsResponse {
    fn from_bytes(buffer: &[u8]) -> DnsResponse {
        let mut offset = size_of::<DnsHeader>();
        let header = DnsHeader::try_ref_from_bytes(&buffer[0..offset]).unwrap();
        let questions = Self::parse_questions(buffer, &mut offset, header.questions.into());
        let answers = Self::parse_answers(buffer, &mut offset, header.answer_rr.into());
        let authority_rr = Self::parse_answers(buffer, &mut offset, header.authority_rr.into());
        let additional_rr = Self::parse_answers(buffer, &mut offset, header.authority_rr.into());
        DnsResponse {
            header: *header,
            questions,
            answers,
            authority_rr,
            additional_rr,
        }
    }

    fn parse_questions(
        buffer: &[u8],
        offset: &mut usize,
        questions_len: usize,
    ) -> Vec<DnsQuestion> {
        let mut questions = Vec::new();
        for _ in 0..questions_len {
            let null_byte = buffer
                .iter()
                .enumerate()
                .skip(*offset)
                .find(|&(_, &b)| b == 0)
                .map(|(i, _)| i)
                .unwrap();
            let question = DnsQuestion::from_bytes(buffer, offset, null_byte);
            questions.push(question);
            *offset = null_byte + 5;
        }
        questions
    }

    fn parse_answers(buffer: &[u8], offset: &mut usize, answer_len: usize) -> Vec<DnsAnswer> {
        let mut answers = Vec::new();
        for _ in 0..answer_len {
            let answer = DnsAnswer::from_bytes(buffer, offset);
            answers.push(answer);
        }
        answers
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct DnsAnswer {
    name: String,
    qtype: QueryType,
    qclass: QueryClass,
    ttl: u32,
    data_len: u16,
    pub answer: Answer,
}

impl DnsAnswer {
    fn from_bytes(buffer: &[u8], offset: &mut usize) -> DnsAnswer {
        match buffer[*offset] {
            0xc0 => Self::parse_name_ptr(buffer, offset),
            _ => Self::parse_name(buffer, offset),
        }
    }

    fn parse_name(_buffer: &[u8], _offset: &mut usize) -> DnsAnswer {
        todo!()
    }

    fn parse_name_ptr(buffer: &[u8], offset: &mut usize) -> DnsAnswer {
        let name_offset = u16::from_be_bytes([buffer[*offset], buffer[*offset + 1]]) ^ (0b11 << 14);
        let name = Self::get_name(buffer, name_offset.into());
        *offset += 2;
        let qtype = QueryType::from_u16(u16::from_be_bytes([buffer[*offset], buffer[*offset + 1]]))
            .unwrap();
        *offset += 2;
        let qclass =
            QueryClass::from_u16(u16::from_be_bytes([buffer[*offset], buffer[*offset + 1]]))
                .unwrap();
        *offset += 2;
        let ttl = u32::from_be_bytes([
            buffer[*offset],
            buffer[*offset + 1],
            buffer[*offset + 2],
            buffer[*offset + 3],
        ]);
        *offset += 4;
        let data_len = u16::from_be_bytes([buffer[*offset], buffer[*offset + 1]]);
        *offset += 2;
        let answer = Answer::new(&buffer[*offset..*offset + data_len as usize]);
        *offset += data_len as usize;
        DnsAnswer {
            name,
            qtype,
            qclass,
            ttl,
            data_len,
            answer,
        }
    }

    fn get_name(buffer: &[u8], offset: usize) -> String {
        let null_byte = buffer
            .iter()
            .enumerate()
            .skip(offset)
            .find(|&(_, &b)| b == 0)
            .map(|(i, _)| i)
            .unwrap();
        let mut name = String::new();
        let name_buff = &buffer[offset..null_byte];
        let mut i = 0;
        while i < name_buff.len() {
            let length = name_buff[i] as usize;
            if length == 0 {
                break;
            }
            i += 1;
            let part = &name_buff[i..i + length];
            name.push_str(&String::from_utf8_lossy(part));
            name.push('.');
            i += length;
        }
        if name.ends_with('.') {
            name.pop();
        }
        name
    }
}

#[derive(Debug)]
pub enum Answer {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Name(String),
}

impl Answer {
    fn new(payload: &[u8]) -> Answer {
        match payload.len() {
            4 => Answer::Ipv4(Ipv4Addr::new(
                payload[0], payload[1], payload[2], payload[3],
            )),
            16 => Answer::Ipv6(Ipv6Addr::from(
                <&[u8] as TryInto<[u8; 16]>>::try_into(payload).unwrap(),
            )),
            _ => Answer::Name(
                String::from_utf8(payload.to_vec())
                    .map_err(|_| "Invalid UTF-8 data")
                    .unwrap(),
            ),
        }
    }
}

pub fn dns_query(domain: &str, qtype: QueryType) -> io::Result<DnsResponse> {
    let packet = DnsQuery::new_query(domain, qtype);
    let dns_servers = get_dns_servers().unwrap();
    let dns_server: IpAddr = dns_servers
        .first()
        .unwrap()
        .parse()
        .expect("Failed to parse DNS server IP address");
    let socket = match dns_server {
        IpAddr::V4(_) => UdpSocket::bind("0.0.0.0:0")?,
        IpAddr::V6(_) => UdpSocket::bind("[::]:0")?,
    };
    socket.connect(format!("{}:53", dns_server))?;
    socket.send(&packet.to_bytes())?;
    let mut buf = [0; 1024];
    match socket.recv(&mut buf) {
        Ok(_received) => Ok(DnsResponse::from_bytes(&buf)),
        Err(e) => Err(e),
    }
}

fn get_dns_servers() -> std::io::Result<Vec<String>> {
    let content = fs::read_to_string("/etc/resolv.conf")?;
    let servers = content
        .lines()
        .filter(|line| line.starts_with("nameserver"))
        .map(|line| line.split_whitespace().nth(1).unwrap().to_string())
        .collect();
    Ok(servers)
}
