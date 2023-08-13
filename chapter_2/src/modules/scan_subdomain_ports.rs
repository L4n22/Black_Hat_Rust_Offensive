use std::fs::{File};
use std::io::BufReader;
use std::io::BufRead;
use std::net::{ToSocketAddrs, TcpStream};
use std::time::Duration;
use rayon::ThreadPoolBuilder;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::io::Write;

struct SubdomainPorts {
    subdomain: String,
    open_ports: Vec<u16>
}

pub struct ScanSubdomainPorts {
    subdomains: Vec<SubdomainPorts>,
    port_range: String
}

impl ScanSubdomainPorts {
    pub fn new() -> Self {
        const DEFAULT_PORT_RANGE: &str = "22-1024";
        ScanSubdomainPorts {
            subdomains: Vec::new(),
            port_range: DEFAULT_PORT_RANGE.to_string(),
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

    pub fn scan_port_subdomains_file(&mut self, filename: &str) -> std::io::Result<()> {
        let file_subdomains = File::open(filename)?;
        let reader = BufReader::new(file_subdomains);
        reader.lines().for_each(
            | line | {
                let subdomain = line.unwrap();
                self.scan_ports(subdomain);
        });

        Ok(())
    }

    fn scan_ports(&mut self, subdomain: String)  {
        let port_range: Vec<&str> = self.port_range.split('-').collect();
        let start_port: u16 = port_range[0].parse().unwrap();
        let end_port: u16 = port_range[1].parse().unwrap();
        let timeout = Duration::from_secs(3);
        let thread_pool = ThreadPoolBuilder::new()
            .num_threads(256)
            .build()
            .unwrap();

        println!("Scanning ports for subdomain: {}", subdomain);
        thread_pool.install(|| {
            let open_ports: Vec<u16> = (start_port..=end_port)
                .into_par_iter()
                .filter(|&port| {
                    match format!("{}:{}", subdomain, port).to_socket_addrs() {
                        Ok(mut socket_addrs) => {
                            let is_port_open = socket_addrs.any(|socket_addr| {
                                TcpStream::connect_timeout(&socket_addr, timeout).is_ok()
                            });
                            if is_port_open {
                                println!("Port {} is open on {}", port, subdomain);
                            }
                            is_port_open
                        }
                        Err(_) => false,
                    }
                })
                .collect();

            self.subdomains.push(SubdomainPorts {
                subdomain,
                open_ports,
            });
        });
    }

    pub fn generate_scan_results_report(&self, filename: &str) -> std::io::Result<()> {
        let mut scan_results = File::create(filename)?;
        for subdomain_ports in &self.subdomains {
            write!(scan_results, "{}, [", subdomain_ports.subdomain)?;
            for port in &subdomain_ports.open_ports {
                write!(scan_results, "{}, ", port)?;
            }

            writeln!(scan_results, "]")?;
        }

        Ok(())
    }
}