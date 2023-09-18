use chapter_4::cli;

fn main() {
    let cli = cli::Cli::parse_args();
    cli.run();
}