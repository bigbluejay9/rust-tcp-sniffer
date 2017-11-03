Laza Upatising

Forwards bytes from SRC:PORT to DEST:PORT, printing what it sees.

```
$ cargo build --release
$ RUST_LOG=level ./target/release/tcp_sniffer DEST:PORT SRC:PORT
```

# RUST_LOG
- RUST_LOG=debug for full debug info.
- RUST_LOG=warn for just the bytes on the pipe.
