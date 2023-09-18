use reqwest::{Client};

use std::time::Duration;


pub struct WebDisclosure {
    web_requester: Client,

}

impl WebDisclosure {
    pub fn build() -> Result<WebDisclosure, reqwest::Error> {
        let timeout = Duration::from_secs(10);
        let web_requester = Client::builder()
            .timeout(timeout)
            .build()?;

        Ok(WebDisclosure {
            web_requester,
        })
    }


    pub async fn check_disclosure(
        &self,
        url: &str) -> Result<bool, reqwest::Error>
    {
        let response = self.web_requester.get(url).send().await?;
        let is_success = response.status().is_success();
        Ok(is_success)
    }
}