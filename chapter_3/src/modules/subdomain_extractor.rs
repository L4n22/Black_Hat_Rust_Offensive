use std::{
    collections::HashSet,
    hash::{Hash, Hasher},
    time::Duration,
    fs::File,
    io::Write
};
use reqwest::{Client, redirect::Policy};
use serde::Deserialize;
use trust_dns_resolver::{
    AsyncResolver,
    config::{ResolverConfig, ResolverOpts},
};
use futures::{stream, StreamExt};

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

    pub async fn extract(&mut self, domain: &str) -> Result<(), reqwest::Error> {
        let crt_url: String = format!("https://crt.sh/?q=%25.{}&output=json", domain);
        let client = Client::builder()
            .redirect(Policy::limited(4))
            .timeout(Duration::from_secs(20))
            .build()?;
        let response: Vec<Subdomain> = client.get(crt_url)
            .send()
            .await?
            .json()
            .await?;

        self.subdomains = response
            .iter()
            .flat_map(|subdomain| subdomain.name_value.split('\n'))
            .map(|name_value| name_value
                .strip_prefix("*.")
                .unwrap_or(name_value).to_string())
            .collect();

            Ok(())
    }

    pub async fn filter_responsive_subdomains(&mut self) {
        let resolver_config = ResolverConfig::default();
        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.timeout = Duration::from_secs(5);
        let async_resolver = AsyncResolver::tokio(
            resolver_config,
            resolver_opts
        ).expect("Failed to create resolver.");
        self.responsive_subdomains = stream::iter(self.subdomains.iter())
            .filter(|&subdomain| {
                let resolver = async_resolver.clone();
                async move {
                    resolver.lookup_ip(subdomain).await.is_ok()
                }
            })
            .map(|subdomain| subdomain.to_string())
            .collect()
            .await;
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