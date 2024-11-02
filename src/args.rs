use clap::Parser;

#[derive(Parser, Debug)]
pub(crate) struct Args {
    // #[arg(short, long)]
    pub(crate) destination: String,
    // #[arg(short, optional)]
    // count: u16,
    #[arg(short, default_value_t = 1.)]
    pub(crate) interval: f64,
}
