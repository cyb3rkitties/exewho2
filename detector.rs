use enigo::Enigo; 
use std::path::Path;
use walkdir::WalkDir;
use std::time::Instant;
use std::collections::HashMap;
use crypto::md5::Md5;
use crypto::sha2::Sha256;
use crypto::sha1::Sha1;
use crypto::digest::Digest;
use std::env;
use std::io::prelude::*;
use std::fs::File;

// Check for mouse pointer activity and sleep patching
fn mouse_activity_sleep_patch()->bool {
    // Check initial location
    let initial_cursor_location: (i32, i32) = Enigo::mouse_location();
    let ix = initial_cursor_location.0;
    let iy = initial_cursor_location.1;

    // Set sleep duration
    let duration = std::time::Duration::new(10,0);

    // Sleep for 10s
    let start = Instant::now();
    std::thread::sleep(duration);
    let elapsed = start.elapsed();

    // Check cursor final location
    let final_cursor_location: (i32, i32) = Enigo::mouse_location();
    let fx = final_cursor_location.0;
    let fy = final_cursor_location.1;

    if ix == fx || iy == fy || (fy-iy) == (fx-ix) {
        return false;
    }

    let lower_limit = 9050 as u128;
    let upper_limit = 10050 as u128;
    let delta: u128 = elapsed.as_millis();
    if delta < lower_limit || delta > upper_limit {
        return false;
    }

    true
}


// Check for Common files found in Sandboxes
fn check_sandbox_files() -> bool {
    let sus_files: [& 'static str; 32] = [ "C:\\Windows\\System32\\drivers\\Vmmouse.sys",
		"C:\\Windows\\System32\\drivers\\vm3dgl.dll", "C:\\Windows\\System32\\drivers\\vmdum.dll",
		"C:\\Windows\\System32\\drivers\\vm3dver.dll", "C:\\Windows\\System32\\drivers\\vmtray.dll",
		"C:\\Windows\\System32\\drivers\\vmci.sys", "C:\\Windows\\System32\\drivers\\vmusbmouse.sys",
		"C:\\Windows\\System32\\drivers\\vmx_svga.sys", "C:\\Windows\\System32\\drivers\\vmxnet.sys",
		"C:\\Windows\\System32\\drivers\\VMToolsHook.dll", "C:\\Windows\\System32\\drivers\\vmhgfs.dll",
		"C:\\Windows\\System32\\drivers\\vmmousever.dll", "C:\\Windows\\System32\\drivers\\vmGuestLib.dll",
		"C:\\Windows\\System32\\drivers\\VmGuestLibJava.dll", "C:\\Windows\\System32\\drivers\\vmscsi.sys",
		"C:\\Windows\\System32\\drivers\\VBoxMouse.sys", "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
		"C:\\Windows\\System32\\drivers\\VBoxSF.sys", "C:\\Windows\\System32\\drivers\\VBoxVideo.sys",
		"C:\\Windows\\System32\\vboxdisp.dll", "C:\\Windows\\System32\\vboxhook.dll",
		"C:\\Windows\\System32\\vboxmrxnp.dll", "C:\\Windows\\System32\\vboxogl.dll",
		"C:\\Windows\\System32\\vboxoglarrayspu.dll", "C:\\Windows\\System32\\vboxoglcrutil.dll",
		"C:\\Windows\\System32\\vboxoglerrorspu.dll", "C:\\Windows\\System32\\vboxoglfeedbackspu.dll",
		"C:\\Windows\\System32\\vboxoglpackspu.dll", "C:\\Windows\\System32\\vboxoglpassthroughspu.dll",
		"C:\\Windows\\System32\\vboxservice.exe", "C:\\Windows\\System32\\vboxtray.exe",
		"C:\\Windows\\System32\\VBoxControl.exe"];

    let mut count = 0;
    for path in sus_files.iter() {
        if Path::new(path).exists(){
            if cfg!(debug_assertions) {
                println!("[!] Found {}", path);
            }
            count += 1;
        }
    }
        
    if count == 0 {
        return true;
    }
    true
}


// Check if Filename is the hash of the file
fn check_filename_hash()->bool{
	let mut md5 = Md5::new();
	let mut sha256 = Sha256::new();
	let mut sha1 = Sha1::new();
	let mut buffer = Vec::new();

    let path = match env::current_exe(){
        Ok(_val) => _val,
        Err(_e) => {
            return false;
        }
    };

	let mut f = match File::open(&path){
        Ok(_val) => _val,
        Err(_e) => {
            return false;
        }
    };

	match f.read_to_end(&mut buffer){
        Ok(_val) => _val,
        Err(_e) => {
            return false;
        },
    };

	md5.input(&buffer);
	sha256.input(&buffer);
	sha1.input(&buffer);
	
    let md5_hash = md5.result_str();
	let sha256_hash = sha256.result_str();
	let sha1_hash = sha1.result_str();
	let file_name = path.file_stem().expect("Failed to extact file name").to_string_lossy();
	
    if md5_hash == file_name || sha256_hash == file_name || sha1_hash == file_name {
		return false;
	} else {
        return true;
	}
}


pub fn check_sandbox()->bool{
    if cfg!(debug_assertions) {
        println!("[i] Checking Cursor Activity & Sleep Patching");
    }
    
    let mut flag = mouse_activity_sleep_patch() ;

    if cfg!(debug_assertions) {
        println!("[i] Checking for Sandbox Files");
    }
    flag = flag & check_sandbox_files();
    
    if cfg!(debug_assertions) {
        println!("[i] Checking for Filename Hash");
    }
    flag = flag & check_filename_hash();

    flag
}