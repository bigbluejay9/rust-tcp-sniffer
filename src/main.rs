extern crate getopts;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate mio;

use getopts::Options;
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use mio::*;
use std::io::{Read, Write};
use std::io::ErrorKind::WouldBlock;
use mio::net::{TcpListener, TcpStream};

fn print_usage(prog: &str, opts: Options) {
    let brief = format!("Usage: {} LISTEN-ADDRESS FORWARD-ADDRESS", prog);
    print!("{}", opts.usage(&brief));
}

const SERVER: mio::Token = mio::Token(0);

fn start_sniffing(lis: &SocketAddr, fwd: &SocketAddr) -> Result<(), std::io::Error> {
    let listener = TcpListener::bind(lis)?;
    let poll = Poll::new()?;
    // SERVER + 1.
    let mut token_counter = 1;
    // Map k: My Token -> (My TcpStream, My Write Buffer, Fwd Stream Token)
    let mut event_map: HashMap<Token, (TcpStream, bool, Vec<u8>, mio::Ready, Token)> =
        HashMap::new();

    poll.register(&listener, SERVER, Ready::readable(), PollOpt::edge())
        .unwrap();

    let mut events = Events::with_capacity(1024);
    loop {
        debug!("poll: {:?}", event_map);
        poll.poll(&mut events, None).unwrap();

        for event in events.iter() {
            debug!("Iterating through events. Current event: {:?}.", event);
            match event.token() {
                SERVER => {
                    let conn = listener.accept()?;
                    handle_new_connection(conn, &poll, token_counter, &mut event_map, fwd)?;
                    token_counter += 2;
                }
                // Fowarding
                ref token => {
                    handle_event(&poll, token, &mut event_map)?;
                }
            }
        }
    }
}

// Connects to fwd, register readable c on poll at token_counter. Adds fwd TcpStream to
// event_map.
fn handle_new_connection(
    (c, _remote): (TcpStream, SocketAddr),
    poll: &Poll,
    token_counter: usize,
    event_map: &mut HashMap<Token, (TcpStream, bool, Vec<u8>, mio::Ready, Token)>,
    fwd: &SocketAddr,
) -> Result<(), std::io::Error> {
    debug!("Accepted connection: {:?}.", c);
    debug!("Dialing: {:?}.", fwd);
    let (upstreamer, downstreamer) = (Token(token_counter), Token(token_counter + 1));
    let conn = match TcpStream::connect(fwd) {
        Ok(c) => c,
        Err(e) => {
            warn!("Can't connect to forward address: {}.", e.to_string());
            return Ok(());
        }
    };

    debug!(
        "Registering upstreamer & downstreamer: \
        between {:?} and {:?}, tokens {:?} and {:?}.",
        c,
        conn,
        &upstreamer,
        &downstreamer
    );
    let upstream_monitor = Ready::readable();
    poll.register(
        &c,
        upstreamer,
        upstream_monitor,
        PollOpt::edge(),
    )?;

    let downstream_monitor = Ready::empty();
    poll.register(
        &conn,
        downstreamer,
        downstream_monitor,
        PollOpt::edge(),
    )?;
    // Insert downstream -> upstream.
    event_map.insert(upstreamer, (
        c,
        false,
        Vec::new(),
        upstream_monitor,
        downstreamer,
    ));
    // Insert upstream -> downstream.
    event_map.insert(downstreamer, (
        conn,
        false,
        Vec::new(),
        downstream_monitor,
        upstreamer,
    ));

    Ok(())
}

fn maybe_write(dest: &mut TcpStream, data: &mut Vec<u8>) -> Result<usize, std::io::Error> {
    let mut written_bytes = Vec::with_capacity(data.len());
    let mut count = 0;
    loop {
        if data.len() == 0 {
            break;
        }
        match dest.write(&data) {
            Ok(w) => {
                written_bytes.extend(data.drain(0..w).collect::<Vec<u8>>().clone());
                count += w;
            }
            Err(ref e) if e.kind() == WouldBlock => {
                break;
            }
            Err(e) => return Err(e),
        }
    }
    warn!(
        "Written {} bytes: {:?}.",
        count,
        String::from_utf8(written_bytes).unwrap()
    );
    Ok(count)
}

fn maybe_read(
    poll: &Poll,
    e: &Token,
    event_map: &mut HashMap<Token, (TcpStream, bool, Vec<u8>, mio::Ready, Token)>,
) -> Result<usize, std::io::Error> {
    debug!("Maybe reading {:?}", e);
    let mut total_read = Vec::new();
    let write_token: Token;
    {
        // Mut borrow scope for read TcpStream.
        let &mut (ref mut read, _, _, _, wt) = event_map.get_mut(e).expect(&format!(
            "event map lacking read entry {:?}",
            e
        ));
        assert!(wt != *e);
        write_token = wt;
        let mut buf = [0; 256];
        loop {
            match read.read(&mut buf) {
                Ok(b) => {
                    if b == 0 {
                        if total_read.len() == 0 {
                            return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "EOF"));
                        }
                        break;
                    }
                    total_read.extend_from_slice(&buf[0..b])
                }
                Err(ref e) if e.kind() == WouldBlock => {
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        warn!(
            "Read {} bytes: {:?}.",
            total_read.len(),
            String::from_utf8(total_read.clone()).unwrap()
        );
    }

    // If we read something, put it on the destination TcpStream and register
    // kevent.
    let len = total_read.len();
    if len > 0 {
        let &mut (ref write, _, ref mut write_buf, monitor, _) =
            event_map.get_mut(&write_token).expect(&format!(
                "event map lacking write buf dest entry {:?}",
                &write_token
            ));
        write_buf.extend(total_read);
        if write_buf.len() > 0 {
            poll.reregister(
                write,
                write_token,
                monitor | Ready::writable(),
                PollOpt::edge(),
            )?;
        }
    }
    Ok(len)
}

fn handle_event(
    poll: &Poll,
    e: &Token,
    event_map: &mut HashMap<Token, (TcpStream, bool, Vec<u8>, mio::Ready, Token)>,
) -> Result<(), std::io::Error> {
    debug!("Handling event: {:?}", e);
    match maybe_read(poll, e, event_map) {
        Err(ref err) if err.kind() == std::io::ErrorKind::BrokenPipe => {
            // Shutdown(write) other side.
            let remove_self;
            {
                let &(_, already_shutdown, _, _, other) = event_map.get(e).unwrap();
                remove_self = already_shutdown;
                match event_map.get_mut(&other) {
                    Some(&mut (ref mut write, ref mut shutdown, _, _, _)) => {
                        *shutdown = true;
                        write.shutdown(std::net::Shutdown::Write)?;
                    }
                    None => debug!("Other pipe already gone."),
                };
            }
            // If out write's already been shutdown, then close.
            if remove_self {
                {
                    let &(ref c, _, _, _, _) = event_map.get(e).unwrap();
                    poll.deregister(c)?;
                }
                event_map.remove(e);
            }
            return Ok(());
        }
        _ => {}
    }
    {
        // Mutable borrow of TcpStream and pending write buf identified by e.
        let &mut (ref mut stream, shutdown, ref mut buf, _, _) =
            event_map.get_mut(e).expect(&format!(
                "event map lacking write entry {:?}",
                e
            ));
        maybe_write(stream, buf)?;
        if shutdown && buf.len() > 0 {
            warn!(
                "Discarding bytes: {:?}",
                String::from_utf8(buf.clone()).unwrap()
            );
        }

        let monitor = match buf.len() {
            0 => Ready::readable(),
            _ => Ready::readable() | Ready::writable(),
        };
        poll.reregister(stream, *e, monitor, PollOpt::edge())?;
    }
    Ok(())
}

fn parse_cmd_line(free: &Vec<String>) -> Result<(SocketAddr, SocketAddr), String> {
    if free.len() < 2 {
        return Err("Not enough args.".to_string());
    } else if free.len() > 2 {
        let extraneous = free[2..].join(",");
        warn!(
            "Too many args provided! Ignoring extraneous args: {}.",
            extraneous
        );
    }

    let lis = try!(
        free[0]
            .replace("localhost", "127.0.0.1")
            .parse::<SocketAddr>()
            .map_err(|e| format!("'{}': {}", free[0], e.to_string()))
    );
    let fwd = try!(
        free[1]
            .replace("localhost", "127.0.0.1")
            .parse::<SocketAddr>()
            .map_err(|e| format!("'{}': {}", free[1], e.to_string()))
    );
    Ok((lis, fwd))
}

fn main() {
    env_logger::init().unwrap();

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "print help menu");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            panic!(f.to_string());
        }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    let (lis, fwd) = match parse_cmd_line(&matches.free) {
        Ok(tup) => (tup.0, tup.1),
        Err(e) => {
            println!("Bad arguments: {}.", e.to_string());
            return;
        }
    };

    match start_sniffing(&lis, &fwd) {
        Err(e) => {
            error!("Server loop failed: {}.", e.to_string());
        }
        _ => {}
    }
}
