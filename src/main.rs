#![feature(maybe_uninit_array_assume_init)]
#![feature(maybe_uninit_slice)]

mod args;
mod icmp;
mod packet;
mod ping;

use crate::args::Args;
use clap::Parser;
use std::io;

fn main() -> io::Result<()> {
    let args = Args::parse();
    ping::send_ping(&args)?;
    Ok(())
}
