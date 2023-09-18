use crate::scanner::web::disclosure::WebDisclosure;
use clap::{Args, Parser, Subcommand, ValueEnum};
use futures::{stream, StreamExt};
use tokio::runtime;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    commands: Commands,
}

impl Cli {
    pub fn parse_args() -> Self {
        Self::parse()
    }

    pub fn run(&self) {
        match &self.commands {
            Commands::ScanWeb(scan_web) => match &scan_web.mode {
                ScanWebMode::Disclosure => {
                    let paths = vec![
                        "/.env",
                        "/.DS_Store",
                        "/.git/HEAD",
                        "/robots.txt",
                        "/sitemap.xml",
                        "/version"
                    ];
                    let host = scan_web.host.as_str();
                    runtime::Builder::new_multi_thread()
                        .worker_threads(100)
                        .enable_all()
                        .build()
                        .unwrap()
                        .block_on(async {
                            let paths_iter = paths.into_iter();
                                stream::iter(paths_iter)
                                .for_each_concurrent(20, |path| {
                                    let url = format!("https://{}{}", host, path);
                                    async move {
                                        let web_disclosure = WebDisclosure::build().unwrap();
                                        let check_disclosure = web_disclosure.check_disclosure(&url).await.unwrap();
                                        if check_disclosure {
                                            eprintln!("URL found: {}", url);
                                        }
                                    }
                                }).await;
                        });
                },
                ScanWebMode::BannerGrabbing => {
                    todo!()
                }
            },
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Web scanning")]
    ScanWeb(ScanWeb),
}

#[derive(Args)]
struct ScanWeb {
    host: String,

    #[arg(value_enum)]
    mode: ScanWebMode,

    #[arg(long, help = "Enable verbose output", required = false)]
    verbose: bool,
}

#[derive(ValueEnum, Clone)]
enum ScanWebMode {
    #[value(help = "Scan for possible exposed sensitive files")]
    Disclosure,
    BannerGrabbing
}

