use std::io;
use std::io::{Read, Write};

use hex;
use base64;

pub(crate) fn hex_encode_cmd() {
    // Stream from stdin to stdout in chunks of 1 kb
    let mut buf: [u8; 1024] = [0u8; 1024];
    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    while bytes_read == 1024 {
        print!("{}", hex::encode(&buf));
        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    }
    print!("{}", hex::encode(&buf));
}

pub(crate) fn hex_decode_cmd() {
    // Stream from stdin to stdout in chunks of 1 kb
    let mut buf: [u8; 1024] = [0u8; 1024];
    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    let mut chunk_str: String = String::from_utf8(Vec::from(buf.as_slice())).unwrap();
    while bytes_read == 1024 {
        io::stdout().write_all(&*hex::decode(chunk_str.as_str()).unwrap()).expect("Failed to write to stdout");

        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
        chunk_str = String::from_utf8(Vec::from(buf.as_slice())).unwrap();
    }
    io::stdout().write_all(&*hex::decode(chunk_str.as_str()).unwrap()).expect("Failed to write to stdout");
}

pub(crate) fn base64_encode_cmd() {
    let mut encoder = base64::Base64Encoder::new();
    // Stream from stdin to stdout in chunks of 1 kb
    let mut buf: [u8; 1024] = [0u8; 1024];
    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    while bytes_read == 1024 {
        print!("{}", encoder.do_update(&buf));
        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    }
    print!("{}", encoder.do_final(&buf[..bytes_read]));
}

pub(crate) fn base64_decode_cmd() {
    // Stream from stdin to stdout in chunks of 1 kb
    let mut buf: [u8; 1024] = [0u8; 1024];
    let mut decoder = base64::Base64Decoder::new(true);
    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    let mut chunk_str: String = String::from_utf8(Vec::from(buf.as_slice())).unwrap();
    while bytes_read == 1024 {
        io::stdout().write_all(decoder.do_update(chunk_str.as_str()).unwrap().as_slice()).expect("Failed to write to stdout");

        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
        chunk_str = String::from_utf8(Vec::from(buf.as_slice())).unwrap();
    }
    io::stdout().write_all(decoder.do_final(chunk_str.as_str()).unwrap().as_slice()).expect("Failed to write to stdout");
}