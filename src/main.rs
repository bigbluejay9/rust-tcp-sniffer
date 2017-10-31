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
use std::io::{self, Write};
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
    let mut event_map: HashMap<Token, (TcpStream, Vec<u8>)> = HashMap::new();

    poll.register(&listener, SERVER, Ready::readable(), PollOpt::edge())
        .unwrap();

    let mut events = Events::with_capacity(1024);
    loop {
        poll.poll(&mut events, None).unwrap();

        for event in events.iter() {
            match event.token() {
                SERVER => {
                    let conn = listener.accept()?;
                    token_counter += 1;
                    handle_new_connection(conn, &poll, token_counter, &mut event_map, fwd)?;
                }
                // Fowarding
                ref token => {
                    handle_event(token, &mut event_map)?;
                }
            }
        }
    }
}

// Connects to fwd, register readable c on poller at token_counter. Adds fwd TcpStream to
// event_map.
fn handle_new_connection(
    (c, remote): (TcpStream, SocketAddr),
    poller: &Poll,
    token_counter: usize,
    event_map: &mut HashMap<Token, (TcpStream, Vec<u8>)>,
    fwd: &SocketAddr,
) -> Result<(), std::io::Error> {
    debug!("Accepted connection: {:?}.", c);
    debug!("Dialing: {:?}.", fwd);
    event_map.insert(Token(token_counter), (TcpStream::connect(fwd)?, Vec::new()));
    debug!(
        "Registering on listenable connection from {:?}, token {}.",
        remote,
        token_counter
    );
    poller.register(
        &c,
        Token(token_counter),
        Ready::readable(),
        PollOpt::edge(),
    )?;
    Ok(())
}

fn handle_event(
    e: &Token,
    event_map: &mut HashMap<Token, (TcpStream, Vec<u8>)>,
) -> Result<(), std::io::Error> {
    debug!("Handling event: {:?}", e);
    let handler = event_map.get(e).expect(
        &format!("event map lacking entry {:?}", e),
    );
    if handler.1.len() > 0 {
        let mut buf = [0; handler.1.len()];
        loop {
            match handler.0.write(handler.1) {
                Ok(wrote) => {
                    handler.1 = handler.1[wrote:]
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break;
                }
                e => panic!("err = {:?}", e),
            }
        }
        // Write.
    }
    Ok(())
}

fn parse_cmd_line(free: &Vec<String>) -> Result<(SocketAddr, SocketAddr), String> {
    warn!("{}", free.len());
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
