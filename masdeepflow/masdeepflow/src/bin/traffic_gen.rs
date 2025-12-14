use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use std::thread;
use std::time::Duration;

fn main() -> std::io::Result<()> {
    println!("Connecting to 1.1.1.1:80...");
    let stream = TcpStream::connect("1.1.1.1:80")?;
    let fd = stream.as_raw_fd();

    let request = "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nUser-Agent: traffic-gen-demo\r\nConnection: close\r\n\r\n";

    println!("Sending request via direct libc::write (fd: {})...", fd);

    // Explicitly use libc::write to ensure we hit the syscall our eBPF traces
    let ret = unsafe { libc::write(fd, request.as_ptr() as *const libc::c_void, request.len()) };

    if ret < 0 {
        eprintln!("Write failed!");
    } else {
        println!("Sent {} bytes.", ret);
    }

    println!("Waiting for response...");
    thread::sleep(Duration::from_millis(500));

    // Read response to trigger sys_read for eBPF capture
    let mut buffer = [0u8; 1024];
    let read_ret =
        unsafe { libc::read(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len()) };

    if read_ret > 0 {
        println!("Received {} bytes response.", read_ret);
    } else {
        println!("No response or read failed.");
    }

    println!("Done.");
    Ok(())
}
