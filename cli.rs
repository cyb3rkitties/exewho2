use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use std::error::Error;
use std::fmt;
use url::Url;

#[derive(Clone, Debug)]
pub struct LoaderOptions {
    pub url: Url,                // Store url to fetch json from
    pub key: Option<String>,     // Decryption key
    pub detect_sandbox: bool,    // Detect Sandbox/Debugger
}

impl fmt::Display for LoaderOptions {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Get Server url
        let mut msg = format!("[i] JSON Server URL:\t\t{}", self.url);
        
        msg = format!(
            "{}\n[i] Sandbox Detection\t\t{}",
            msg,
            match self.detect_sandbox {
                true => "ON",
                false => "OFF",
            }
        );

        if self.key.is_some() {
            msg = format!("{}\n[i] Decryption Key:\t\t{}", msg, self.key.clone().unwrap());
        }

        write!(f, "{}", msg)
    }
}

impl LoaderOptions {
    pub fn new(cmds: ArgMatches) -> Result<LoaderOptions, Box<dyn Error>> {
        // Closure ton get bool flags for various loader options
        let check_bool = |option: &str| -> bool {
            match cmds.get_one::<bool>(option) {
                Some(v) => *v,
                None => false,
            }
        };

        // Get url of the endpoint
        let url: Url = match cmds.get_one::<String>("url") {
            Some(v) => match Url::parse(v) {
                Ok(u) => u,
                Err(e) => {
                    return Err(e.into());
                }
            },
            None => {
                return Err("No URL supplied!".into());
            }
        };

        // Check for decryption key
        let key: Option<String> = cmds.get_one::<String>("dec_key").cloned();

        // Detect Sandbox
        let detect_sandbox: bool = check_bool("detect_sandbox");
        return Ok(LoaderOptions { url, key, detect_sandbox });
    }
}

// Function to fetch cli args
pub fn get_cli_args() -> Result<LoaderOptions, Box<dyn Error>> {
    let matches: ArgMatches = Command::new("ExeWho2")
        .about("Run executables in Memory, but better!")
        .arg(
            Arg::new("url")
                .short('u')
                .long("url")
                .help("URL to fetch Server Listings from")
                .required(true),
        )
        .arg(
            Arg::new("detect_sandbox")
                .long("ds")
                .help("Try to detect if loader is in a Sandbox")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("dec_key")
                .short('k')
                .long("key")
                .help("Key for decrypting incoming stream(if encrypted)"),
        )
        .get_matches();

    return LoaderOptions::new(matches);
}
