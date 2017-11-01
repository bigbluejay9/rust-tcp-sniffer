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
    let mut event_map: HashMap<Token, (TcpStream, Vec<u8>, &Token)> = HashMap::new();

    poll.register(&listener, SERVER, Ready::readable(), PollOpt::edge())
        .unwrap();

    let mut events = Events::with_capacity(1024);
    loop {
        debug!("poll");
        poll.poll(&mut events, None).unwrap();
        debug!("poll return");

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
    event_map: &mut HashMap<Token, (TcpStream, Vec<u8>, &Token)>,
    fwd: &SocketAddr,
) -> Result<(), std::io::Error> {
    debug!("Accepted connection: {:?}.", c);
    debug!("Dialing: {:?}.", fwd);
    let (upstreamer, downstreamer) = (Token(token_counter),
        Token(token_counter+1));
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
        c, conn, &upstreamer, &downstreamer);
    // Insert downstream -> upstream.
    event_map.insert(upstreamer, (&mut c, Vec::new(), &downstreamer));
    // Insert upstream -> downstream.
    event_map.insert(downstreamer, (conn, Vec::new(), &upstreamer));
    poll.register(
        &c,
        Token(token_counter),
        Ready::readable(),
        PollOpt::edge(),
    )?;
    Ok(())
}

fn maybe_write(
    dest: &mut TcpStream,
    data: &mut Vec<u8>) -> Result<usize, std::io::Error> {
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
    debug!(
        "Written {} bytes: {}.",
        count,
        String::from_utf8(written_bytes).unwrap()
    );
    Ok(count)
}

fn maybe_read(
    poll: &Poll,
    read: &mut TcpStream,
    write_token: &Token,
    write: &mut TcpStream,
    write_buf: &mut Vec<u8>) -> Result<usize, std::io::Error> {
  let mut buf = [0; 256];
  let mut total_read = Vec::new();
  loop {
    match read.read(&mut buf) {
      Ok(b) => {
        total_read.extend_from_slice(&buf[0..b]);
      }
      Err(ref e) if e.kind() == WouldBlock => {
        break;
      }
      Err(e) => return Err(e),
    }
  }
  debug!("Read {} bytes: {}.", total_read.len(),
      String::from_utf8(total_read.clone()).unwrap());
  let len = total_read.len();
  if len > 0 {
    write_buf.extend(total_read);
    poll.reregister(write, *write_token, Ready::readable() | Ready::writable(), PollOpt::edge())?;
  }
  Ok(len)
}

fn handle_event(
    poll: &Poll,
    e: &Token,
    event_map: &mut HashMap<Token, (TcpStream, Vec<u8>, &Token)>,
) -> Result<(), std::io::Error> {
    debug!("Handling event: {:?}", e);
    let read_clone;
    {
    let &mut (ref mut read, ref mut data, ref write) = event_map.get_mut(e).expect(&format!(
        "event map lacking entry {:?}",
        e
    ));
    read_clone = &mut read.try_clone()?;
    }
    let &mut (_, ref mut data, ref write) = event_map.get_mut(e).expect(&format!(
        "event map lacking entry {:?}",
        e
    ));
    {
      let read_clone;
      let write_token;
      {
        let &mut (ref mut read, _, ref wt) =
          event_map.get_mut(e).expect(&format!( "event map lacking read entry {:?}", e));
        read_clone = &mut read.try_clone()?;
        write_token = &wt;
      }
      let &mut (ref mut write, ref mut write_buffer, _) =
          event_map.get_mut(write_token).expect(&format!( "event map lacking write entry {:?}", write_token));
      maybe_read(poll, read_clone, write_token, write, write_buffer);
    }
    maybe_write(read_clone, data)?;

    let mut monitor = Ready::readable();
    if data.len() > 0 {
      monitor |= Ready::writable();
    }
    poll.reregister(read_clone, *e, monitor, PollOpt::edge())?;
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
