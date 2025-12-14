use std::fs::File;
use std::io::prelude::*;
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::thread;
use std::time::Duration;

fn main() -> std::io::Result<()> {
    println!("Connecting to 1.1.1.1:80...");
    let stream = TcpStream::connect("1.1.1.1:80")?;

    // Force usage of `write` syscall by wrapping in File
    // (File uses write() whereas TcpStream might use sendto() or writev())
    let fd = stream.as_raw_fd();
    let mut file = unsafe { File::from_raw_fd(fd) };

    let request = "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nUser-Agent: rust-manual-verify\r\nConnection: close\r\n\r\n";

    println!("Sending request via File::write_all() (syscall: write)...");
    file.write_all(request.as_bytes())?;

    // We cannot read from `file` easily for network without blocking weirdly,
    // but we only care about TX capture.
    // Let's drop file to avoid closing fd twice? No, from_raw_fd takes ownership.
    // But we cloned stream? No.
    // stream.read() might fail if file took ownership.
    // Let's just finish.

    println!("Request sent.");
    thread::sleep(Duration::from_millis(2000));

    // Prevent double close (TcpStream also closes)
    // std::mem::forget(file);
    // Actually from_raw_fd consumer ownership. TcpStream also has it.
    // This will cause double close.
    // Correct way: use into_raw_fd().
    // But TcpStream doesn't implement IntoRawFd easily? It does.
    // let fd = stream.into_raw_fd();
    // let mut file = unsafe { File::from_raw_fd(fd) };

    // Simplified: Just use libc write if possible, but File is easier.
    // We accept double close panic or error at exit, it's just a test tool.
    std::mem::forget(file); // Leak file to prevent closing fd, letting stream close it.

    println!("Done.");
    Ok(())
}
