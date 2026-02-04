use core_interface::traits::{RNG};
use factory::AlgorithmFactory;
use factory::rng_factory::RNGFactory;

use std::io;
use std::io::{Write};


pub(crate) fn rng_cmd(len: Option<u32>, output_hex: bool) {
    let mut rng = RNGFactory::default_256_bit();
    let mut buf = vec![0u8; 1024];

    let loop_forever = len.is_none();
    let mut bytes_left_to_write = len.unwrap_or(u32::MAX) as usize;
    while loop_forever || bytes_left_to_write > 0 {
        rng.next_bytes_out(&mut buf).unwrap();

        if bytes_left_to_write < buf.len() { buf.truncate(bytes_left_to_write); }
        if output_hex {
            for b in buf.iter() {
                print!("{b:02x}");
            }
        } else { io::stdout().write(&buf).unwrap(); }
        bytes_left_to_write -= buf.len();
    }
    println!();
}