use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use std::time::Duration;
use serde::Deserialize;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    Resolver,
};
use std::fs::File;
use std::io::Write;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rayon::ThreadPoolBuilder;

#[derive(
    Debug,
    Deserialize,
    Eq)
]
struct Subdomain {
    //issuer_ca_id: u32,
    //issuer_name: String,
    //common_name: String,
    name_value: String//,
    //id: u32,
    //entry_timestamp: String,
    //not_before: String,
    //not_after: String,
    //serial_number: String
}

impl Hash for Subdomain {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name_value.hash(state);
    }
}

impl PartialEq for Subdomain {
    fn eq(&self, other: &Self) -> bool {
        self.name_value == other.name_value
    }
}

pub struct SubdomainExtractor {
    subdomains: HashSet<String>,
    responsive_subdomains: HashSet<String>
}

impl SubdomainExtractor {
    pub fn new() -> Self {
        SubdomainExtractor {
            subdomains: HashSet::new(),
            responsive_subdomains: HashSet::new()
        }
    }

    pub fn extract(&mut self, domain: &str) -> Result<(), reqwest::Error> {
        let crt_url: String = format!("https://crt.sh/?q=%25.{}&output=json", domain);
        let client = Client::builder()
            .redirect(Policy::limited(4))
            .timeout(Duration::from_secs(20))
            .build()?;
        let response: Vec<Subdomain> = client.get(crt_url).send()?.json()?;
        self.subdomains = response
            .iter()
            .map(|subdomain| subdomain.name_value.split('\n'))
            .flatten()
            .map(|name_value| name_value
                .strip_prefix("*.")
                .unwrap_or(name_value)
                .to_string())
            .collect();

        Ok(())
    }

    pub fn filter_responsive_subdomains(&mut self) {
        let resolver_config = ResolverConfig::default();
        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.timeout = Duration::from_secs(5);
        let resolver = Resolver::new(
            resolver_config,
            resolver_opts
        ).expect("Failed to create resolver.");
        let thread_pool = ThreadPoolBuilder::new()
            .num_threads(256)
            .build()
            .unwrap();
        thread_pool.install(|| {
            self.responsive_subdomains = self.subdomains
                .par_iter()
                .filter(| &subdomain| resolver.lookup_ip(subdomain.as_str()).is_ok())
                .cloned()
                .collect();
        });
    }

    pub fn generate_subdomain_report(&self, filename: &str) -> std::io::Result<()> {
        let mut file_subdomain = File::create(filename)?;
        for subdomain in &self.subdomains {
            writeln!(file_subdomain, "{}", subdomain)?;
        }

        Ok(())
    }

    pub fn generate_responsive_subdomain_report(&self, filename: &str) -> std::io::Result<()> {
        let mut file_responsive_subdomains = File::create(filename)?;
        for responsive_subdomain in &self.responsive_subdomains {
            writeln!(file_responsive_subdomains, "{}", responsive_subdomain)?;
        }

        Ok(())
    }
}