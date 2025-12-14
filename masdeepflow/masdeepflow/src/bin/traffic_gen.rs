use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use std::thread;
use std::time::Duration;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mode = if args.len() > 1 { &args[1] } else { "http" };

    if mode == "mysql-server" {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        println!("Starting Mock MySQL Server on 0.0.0.0:3306...");
        let listener = TcpListener::bind("0.0.0.0:3306")?;

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    println!("New client connected!");
                    let mut buffer = [0u8; 1024];
                    // 1. Read Request
                    let n = stream.read(&mut buffer)?;
                    println!("Received {} bytes (Query).", n);

                    // 2. Simulate Processing Latency
                    thread::sleep(Duration::from_millis(50));

                    // 3. Send Response (MySQL OK Packet)
                    // Packet Length: 7 (0,0,0,2,0,0,0) -> No, Wait.
                    // Standard OK Packet:
                    // Header: [Len=7, Seq=1] (Response seq usually increments)
                    // Payload: [0x00 (OK), 0x00 (Affected Rows), 0x00 (Last Insert ID), ...StatusFlags(2), Warnings(2)]
                    // Let's simpler: Header(4) + Type(1)
                    // Len=1, Seq=1, Type=0x00 (OK) -> [0x01, 0x00, 0x00, 0x01, 0x00]
                    let response = [0x01, 0x00, 0x00, 0x01, 0x00];
                    stream.write_all(&response)?;
                    println!("Sent OK Packet.");
                }
                Err(e) => println!("Connection failed: {}", e),
            }
        }
    } else if mode == "mysql-client" {
        println!("Mode: MySQL Client (Simulated)");
        println!("Connecting to 127.0.0.1:3306...");
        let stream = TcpStream::connect("127.0.0.1:3306")?;
        let fd = stream.as_raw_fd();

        // MySQL Packet Construction
        let sql = "SELECT 1;";
        let mut packet = Vec::new();
        packet.push(0x0A); // Len Low
        packet.push(0x00); // Len Mid
        packet.push(0x00); // Len High
        packet.push(0x00); // Seq (0)
        packet.push(0x03); // Command (COM_QUERY)
        packet.extend_from_slice(sql.as_bytes());

        println!(
            "Sending MySQL COM_QUERY (len={}) via libc::write...",
            packet.len()
        );
        let ret = unsafe { libc::write(fd, packet.as_ptr() as *const libc::c_void, packet.len()) };

        println!("Waiting for response...");
        let mut buffer = [0u8; 1024];
        // Read response to trigger sys_read for eBPF capture
        let read_ret =
            unsafe { libc::read(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len()) };
        println!("Received {} bytes.", read_ret);
    } else if mode == "mysql" {
        println!("Mode: MySQL (Simulated)");
        println!("Connecting to 1.1.1.1:3306...");
        let stream = TcpStream::connect("1.1.1.1:3306")?;
        let fd = stream.as_raw_fd();

        // MySQL Packet Construction
        // Header: [Len_Low, Len_Mid, Len_High, Seq]
        // Payload: [Command, ...SQL...]
        // SQL: "SELECT 1;" (Length = 9)
        // Command: COM_QUERY (0x03) (Length = 1)
        // Total Payload Length: 10 (0x0A)
        let sql = "SELECT 1;";
        let mut packet = Vec::new();
        packet.push(0x0A); // Len Low
        packet.push(0x00); // Len Mid
        packet.push(0x00); // Len High
        packet.push(0x00); // Seq (0)
        packet.push(0x03); // Command (COM_QUERY)
        packet.extend_from_slice(sql.as_bytes());

        println!(
            "Sending MySQL COM_QUERY (len={}) via libc::write...",
            packet.len()
        );
        let ret = unsafe { libc::write(fd, packet.as_ptr() as *const libc::c_void, packet.len()) };
        if ret < 0 {
            eprintln!("Write failed!");
        } else {
            println!("Sent {} bytes.", ret);
        }

        thread::sleep(Duration::from_millis(500));
        println!("Done (No response read implementation for MySQL yet).");
    } else {
        println!("Mode: HTTP (Default)");
        println!("Connecting to 1.1.1.1:80...");
        let stream = TcpStream::connect("1.1.1.1:80")?;
        let fd = stream.as_raw_fd();

        let request = "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nUser-Agent: traffic-gen-demo\r\nConnection: close\r\n\r\n";

        println!("Sending request via direct libc::write (fd: {})...", fd);

        // Explicitly use libc::write to ensure we hit the syscall our eBPF traces
        let ret =
            unsafe { libc::write(fd, request.as_ptr() as *const libc::c_void, request.len()) };

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
    }

    Ok(())
}
