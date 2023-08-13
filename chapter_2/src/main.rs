mod modules;

use modules::subdomain_extractor::SubdomainExtractor;
use crate::modules::scan_subdomain_ports::ScanSubdomainPorts;

fn main() {
    let mut subdomain_extractor = SubdomainExtractor::new();
    let domain = "example.com";
    if let Err(err) = subdomain_extractor.extract(domain) {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    }

    subdomain_extractor.generate_subdomain_report("subdomain.txt")
        .expect("Failed to create file");
    subdomain_extractor.filter_responsive_subdomains();
    subdomain_extractor.generate_responsive_subdomain_report("responsive_subdomain.txt")
        .expect("Failed to create file.");
    println!();
    println!("SubdomainExtractor completed!");
    println!();

    let mut scan_subdomains_ports = ScanSubdomainPorts::new();
    let port_range: &str = "22-1024";
    if scan_subdomains_ports.validate_port_range_format(port_range) {
        scan_subdomains_ports.set_port_range(port_range);
    }

    scan_subdomains_ports.scan_port_subdomains_file("responsive_subdomain.txt")
        .expect("Failed to scan ports.");
    scan_subdomains_ports.generate_scan_results_report("scan_report.txt")
        .expect("Failed to generate scan report.");

    println!("ScanSubdomainPorts Completed!");
}