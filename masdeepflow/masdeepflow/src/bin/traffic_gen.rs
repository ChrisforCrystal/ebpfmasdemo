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
    } else if mode == "benchmark-server" {
        use std::io::Read;
        use std::net::TcpListener;
        println!("Starting Benchmark Server on 0.0.0.0:8080...");
        let listener = TcpListener::bind("0.0.0.0:8080")?;
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    println!("Client connected. Receiving data...");
                    let mut buf = [0u8; 65536];
                    let mut total = 0usize;
                    let start = std::time::Instant::now();
                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) => break, // EOF
                            Ok(n) => total += n,
                            Err(e) => {
                                eprintln!("Read error: {}", e);
                                break;
                            }
                        }
                    }
                    let dur = start.elapsed();
                    let info = format!(
                        "Received {} bytes in {:?}. Speed: {:.2} MB/s",
                        total,
                        dur,
                        (total as f64 / 1024.0 / 1024.0) / dur.as_secs_f64()
                    );
                    println!("{}", info);
                }
                Err(e) => eprintln!("Connection failed: {}", e),
            }
        }
    } else if mode == "benchmark-client" {
        println!("Starting Benchmark Client -> 127.0.0.1:8080 (10s test)...");
        let mut stream = TcpStream::connect("127.0.0.1:8080")?;
        let buf = [1u8; 65536];
        let mut total = 0usize;
        let start = std::time::Instant::now();
        while start.elapsed().as_secs() < 10 {
            use std::io::Write;
            stream.write_all(&buf)?;
            total += buf.len();
        }
        let dur = start.elapsed();
        let info = format!(
            "Sent {} bytes in {:?}. Speed: {:.2} MB/s",
            total,
            dur,
            (total as f64 / 1024.0 / 1024.0) / dur.as_secs_f64()
        );
        println!("{}", info);
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
    } else if mode == "redis-server" {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        println!("Starting Mock Redis Server on 0.0.0.0:6379...");
        let listener = TcpListener::bind("0.0.0.0:6379")?;
        for stream in listener.incoming() {
            if let Ok(mut stream) = stream {
                println!("Redis Client connected!");
                let mut buf = [0u8; 1024];
                loop {
                    let n = stream.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    println!(
                        "Received Redis Command: {:?}",
                        String::from_utf8_lossy(&buf[..n])
                    );
                    // Respond with +OK\r\n (Simple String)
                    stream.write_all(b"+OK\r\n")?;
                }
            }
        }
    } else if mode == "redis-client" {
        use std::io::{Read, Write};
        println!("Connecting to Redis 127.0.0.1:6379...");
        let mut stream = TcpStream::connect("127.0.0.1:6379")?;
        // RESP: *2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n
        let cmd = "*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n";
        stream.write_all(cmd.as_bytes())?;
        println!("Sent Redis Command: GET foo");
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf)?;
        println!(
            "Received Redis Response: {:?}",
            String::from_utf8_lossy(&buf[..n])
        );
    } else if mode == "pg-server" {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        println!("Starting Mock Postgres Server on 0.0.0.0:5432...");
        let listener = TcpListener::bind("0.0.0.0:5432")?;
        for stream in listener.incoming() {
            if let Ok(mut stream) = stream {
                println!("PG Client connected!");
                let mut buf = [0u8; 1024];
                // 1. Read Startup Message (Length + Protocol)
                let _ = stream.read(&mut buf)?;
                // 2. Send AuthOK (R, Len=8, 0)
                stream.write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0])?;
                // 3. Send ReadyForQuery (Z, Len=5, 'I')
                stream.write_all(&[b'Z', 0, 0, 0, 5, b'I'])?;

                loop {
                    let n = stream.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    if buf[0] == b'Q' {
                        let query = String::from_utf8_lossy(&buf[5..n]);
                        println!("Received PG Query: {}", query);
                        // Simulate delay
                        thread::sleep(Duration::from_millis(50));
                        // Send CommandComplete (C)
                        let tag = b"SELECT 1";
                        let mut resp = vec![b'C', 0, 0, 0, (4 + tag.len() + 1) as u8];
                        resp.extend_from_slice(tag);
                        resp.push(0);
                        stream.write_all(&resp)?;
                        // Send ReadyForQuery (Z)
                        stream.write_all(&[b'Z', 0, 0, 0, 5, b'I'])?;
                    }
                }
            }
        }
    } else if mode == "pg-client" {
        use std::io::{Read, Write};
        println!("Connecting to Postgres 127.0.0.1:5432...");
        let mut stream = TcpStream::connect("127.0.0.1:5432")?;

        // 1. Send Startup Message (Len=8, Proto=3.0 -> 0x00030000)
        // Actually startup packet is Length(4) + Proto(4 major.minor) + Params..
        // Minimal: [0,0,0,8, 0,3,0,0] (Length 8 including self)
        stream.write_all(&[0, 0, 0, 8, 0, 3, 0, 0])?;

        // 2. Read AuthOK + ReadyForQuery
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf)?;
        println!("Received Handshake: {:?}", &buf[..n]);

        // 3. Send Simple Query (Q)
        // Q + Len(4) + "SELECT 1" + \0
        let sql = "SELECT 1";
        let mut cmd = vec![b'Q', 0, 0, 0, (4 + sql.len() + 1) as u8];
        cmd.extend_from_slice(sql.as_bytes());
        cmd.push(0);
        stream.write_all(&cmd)?;
        println!("Sent PG Query: SELECT 1");

        // 4. Read Response
        let n = stream.read(&mut buf)?;
        println!(
            "Received PG Response: {:?}",
            String::from_utf8_lossy(&buf[..n])
        );
    } else {
        println!("Mode: HTTP (Default)");
        println!("Connecting to 1.1.1.1:80...");
        let stream = TcpStream::connect("1.1.1.1:80")?;
        let fd = stream.as_raw_fd();
        let request = "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nUser-Agent: traffic-gen-demo\r\nConnection: close\r\n\r\n";
        println!("Sending request via direct libc::write (fd: {})...", fd);
        let ret =
            unsafe { libc::write(fd, request.as_ptr() as *const libc::c_void, request.len()) };
        if ret < 0 {
            eprintln!("Write failed!");
        } else {
            println!("Sent {} bytes.", ret);
        }
        println!("Waiting for response...");
        thread::sleep(Duration::from_millis(500));
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
