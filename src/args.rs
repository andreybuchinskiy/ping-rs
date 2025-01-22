use clap::Parser;

#[derive(Parser, Debug)]
pub struct Args {
    pub destination: String,

    /// Number of packets to send
    #[arg(short = 'c')]
    pub count: Option<u16>,

    /// Interval between sending packets
    #[arg(short, default_value_t = 1.)]
    pub interval: f64,

    /// Force IPv6 pings
    #[arg(short = '6', default_value_t = false)]
    pub ipv6: bool,

    /// Payload size
    #[arg(short = 's', default_value_t = 56)]
    pub payload_len: u16,
}
