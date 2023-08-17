use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use std::net::{ToSocketAddrs};
use std::time::Duration;
use futures::{stream, StreamExt};
use tokio::sync::mpsc;
use tokio::net::TcpStream;


struct SubdomainPorts {
    subdomain: String,
    open_ports: Vec<u16>
}

pub struct ScanSubdomainPorts {
    subdomains: Vec<SubdomainPorts>,
    port_range: String,
    port_concurrency: usize,
    port_timeout_seconds: u64
}

impl ScanSubdomainPorts {
    pub fn new(
        port_range: String,
        port_concurrency: usize,
        port_timeout_seconds: u64) -> Self
    {
        Self {
            subdomains: Vec::new(),
            port_range,
            port_concurrency,
            port_timeout_seconds
        }
    }

    pub fn validate_port_range_format(&self, format: &str) -> bool {
        let re = regex::Regex::new(
            r"(?x)^(1|[1-9]\d{0,3}|[1-5]\d{4}|6[1-4]\d{3}|65[1-4]\d{2}|655[1-2]\d|6553[1-5]) #Start of range
            -(1|[1-9]\d{0,3}|[1-5]\d{4}|6[1-4]\d{3}|65[1-4]\d{2}|655[1-2]\d|6553[1-5])$ #End of range").unwrap();

        re.is_match(format)
    }

    pub fn set_port_range(&mut self, range_ports: &str) {
        self.port_range = range_ports.to_string();
    }

    pub async fn scan_port_subdomains_file(&mut self, filename: &str) -> std::io::Result<()> {
        let file_subdomains = File::open(filename).await?;
        let reader = BufReader::new(file_subdomains);
        let mut lines = reader.lines();
        while let Some(line) = lines.next_line().await? {
            let subdomain = line;
            self.scan_ports(subdomain).await;
        }

        Ok(())
    }

    pub async fn scan_ports(&mut self, subdomain: String)  {
        let port_range: Vec<&str> = self.port_range.split('-').collect();
        let start_port: u16 = port_range[0].parse().unwrap_or_default();
        let end_port: u16 = port_range[1].parse().unwrap_or_default();
        println!("[{}]", subdomain);
        let (output_tx, output_rx) = mpsc::channel(self.port_concurrency);
        stream::iter(start_port..=end_port)
            .for_each_concurrent(self.port_concurrency, |port| {
                let subdomain = subdomain.clone();
                let output_tx = output_tx.clone();
                let timeout = self.port_timeout_seconds.clone();
                async move
                {
                    if let Some(socket_addr) = format!("{}:{}", subdomain, port)
                        .to_socket_addrs()
                        .ok()
                        .and_then(|mut socket_addrs| socket_addrs.next())
                    {
                        if let Ok(_) = tokio::time::timeout(
                            Duration::from_secs(timeout),
                            TcpStream::connect(&socket_addr)).await {
                            println!("{}, open", port);
                            let _ = output_tx.send(port).await;
                        }
                    }
                }
            }).await;

        drop(output_tx);
        let output_rx_stream = tokio_stream::wrappers::ReceiverStream::new(output_rx);
        let open_ports = output_rx_stream.collect().await;
        self.subdomains.push(SubdomainPorts {
            subdomain,
            open_ports,
        });
    }

    pub async fn generate_scan_results_report(&self, filename: &str) -> std::io::Result<()> {
        let mut scan_results = File::create(filename).await?;
        for subdomain_ports in &self.subdomains {
            scan_results.write(subdomain_ports.subdomain.as_bytes()).await?;
            scan_results.write(b", [").await?;
            for port in &subdomain_ports.open_ports {
                scan_results.write(port.to_string().as_bytes()).await?;
                scan_results.write(b", ").await?;
            }

            scan_results.write(b"]\n").await?;
        }

        Ok(())
    }
}