extern crate net2;
extern crate bincode;
extern crate rustc_serialize;
#[macro_use]
extern crate log;
extern crate env_logger;

use std::net::Ipv4Addr;
#[cfg(not(windows))]
use net2::unix::UnixUdpBuilderExt;
use net2::UdpBuilder;
use bincode::rustc_serialize::decode;

#[repr(C)]
#[repr(packed)]
#[derive(Default)]
#[derive(Debug)]
#[derive(RustcEncodable, RustcDecodable)]
struct MDNSPacketHeader {
    id: u16, // transaction ID
    flags: u16,
    num_qn: u16,
    num_ans_rr: u16,
    num_auth_rr: u16,
    num_add_rr: u16,
}

// #[repr(C)]
// #[repr(packed)]
// #[derive(Default)]
// #[derive(Debug)]
// #[derive(RustcEncodable, RustcDecodable)]
// #[derive(Debug)]
// struct MDNSPacketEntry {

// }

#[derive(Debug)]
enum MDNSType {
    A,
    PTR,
    TXT,
    AAAA,
    SRV,
    NSEC,
    ANY,
    UNKNOW(u8),
}

impl MDNSType {
    #[doc(hidden)]
    pub fn from_u8(n: u8) -> MDNSType {
        match n {
            0x01 => MDNSType::A,
            0x0C => MDNSType::PTR,
            0x10 => MDNSType::TXT,
            0x1C => MDNSType::AAAA,
            0x21 => MDNSType::SRV,
            0x2F => MDNSType::NSEC,
            0xFF => MDNSType::ANY,
            _ => MDNSType::UNKNOW(n),
        }
    }

    #[doc(hidden)]
    pub fn to_u8(&self) -> u8 {
        match *self {
            MDNSType::A => 0x01,
            MDNSType::PTR => 0x0C,
            MDNSType::TXT => 0x10,
            MDNSType::AAAA => 0x1C,
            MDNSType::SRV => 0x21,
            MDNSType::NSEC => 0x2F,
            MDNSType::ANY => 0xFF,
            MDNSType::UNKNOW(n) => n,
        }
    }
}

#[derive(Debug)]
struct MDNSData {
    id: u16,
    flags: u16,
    questions: Vec<MDNSQuestion>,
    answers: Vec<MDNSAnswer>,
}

#[derive(Debug)]
struct MDNSQuestion {
    name: String,
    rr_type: MDNSType,
}

#[derive(Debug)]
struct MDNSAnswer {
    id: u16,
    flags: u16,
}

fn decompress_label(packet: &[u8], mut offset: usize) -> (String, usize) {
    let mut full_string = String::new();
    let mut label_offset = 0;

    let mut compressed = false;

    while 0 != packet[offset] {
        if full_string.len() > 0 {
            full_string.push('.');
        }
        let mut string_size = packet[offset];

        trace!("size buffer: {:?}", &packet[offset..(offset + 2)]);

        if 0xC0 == (string_size & 0xC0) {
            compressed = true;
            let small_size = packet[offset + 1];
            trace!("In BIG SIZE: {}", small_size);
            offset = (string_size & 0x3F) as usize;
            trace!("In BIG SIZE_1: {}", offset);
            offset *= 256;
            trace!("In BIG SIZE_2: {}", offset);
            offset += small_size as usize;
            string_size = packet[offset];
            offset += 1;
            trace!("BUFFER: {:?}",
                   &packet[offset..(offset + string_size as usize)]);
            trace!("In BIG SIZE_3: {} {}", offset, string_size);
        } else {
            offset += 1;
            label_offset += 1;
        }
        full_string += std::str::from_utf8(&packet[offset..(offset + string_size as usize)])
            .unwrap();
        offset += string_size as usize;
        if false == compressed {
            label_offset += string_size as usize;
        }
    }
    label_offset += 1;

    trace!("{:?} {}", full_string, label_offset);
    (full_string, label_offset)
}

fn parse_packet(packet: &[u8]) -> Option<MDNSData> {
    let decoded: MDNSPacketHeader = decode(&packet[0..12]).unwrap();

    let mut result = MDNSData {
        id: decoded.id,
        flags: decoded.flags,
        questions: vec![],
        answers: vec![],
    };

    let mut decode_position = std::mem::size_of::<MDNSPacketHeader>();
    for _ in 0..decoded.num_qn {
        let (label_string, label_offset) = decompress_label(packet, decode_position);

        result.questions.push(MDNSQuestion {
            name: label_string,
            rr_type: MDNSType::from_u8(packet[decode_position]),
        });

        decode_position += label_offset;
        trace!("decode buffer({}): {:?}",
               decode_position,
               &packet[decode_position..(decode_position + 4)]);
        decode_position += 4;

        //     let mut full_string = String::new();
        //     while 0 != packet[decode_position] {
        //         if full_string.len() > 0 {
        //             full_string.push('.');
        //         }
        //         let string_size = packet[decode_position];
        //         if 0xC0 == (string_size & 0xC0) {
        //             let new of
        //         }
        //         decode_position += 1;
        //         full_string += std::str::from_utf8(&packet[decode_position..(decode_position +
        //                                                                      string_size as usize)])
        //             .unwrap();
        //         decode_position += string_size as usize;
        //     }
        //     decode_position += 1;

        //     result.questions.push(MDNSQuestion {
        //         name: full_string,
        //         rr_type: MDNSType::from_u8(packet[decode_position]),
        //     });

        //     // println!("result: {}", full_string);
        //     println!("QUESTION: {:?}",
        //              &packet[decode_position..(decode_position + 24)]);
    }

    // udp_socket.send_to(&packet[..], &src);

    trace!("{:?}", decoded);
    // println!("{:?}", &packet[0..32]);

    Some(result)
}


fn main() {
    env_logger::init().unwrap();

    let udp_builder = UdpBuilder::new_v4().unwrap();

    match udp_builder.reuse_address(true) {
        Ok(s) => s,
        Err(e) => panic!("couldn't reuse_address: {}", e),
    };

    match udp_builder.reuse_port(true) {
        Ok(s) => s,
        Err(e) => panic!("couldn't reuse_address: {}", e),
    };

    let udp_socket = match udp_builder.bind("224.0.0.251:5353") {
        Ok(s) => s,
        Err(e) => panic!("couldn't bind: {}", e),
    };

    let ip_mdns = Ipv4Addr::new(224, 0, 0, 251);
    let ip_any = Ipv4Addr::new(0, 0, 0, 0);

    match udp_socket.join_multicast_v4(&ip_mdns, &ip_any) {
        Ok(s) => s,
        Err(e) => panic!("couldn't join_multicast_v4: {}", e),
    };

    match udp_socket.set_multicast_loop_v4(true) {
        Ok(s) => s,
        Err(e) => panic!("couldn't set_multicast_loop_v4: {}", e),
    };

    info!("start reading");

    loop {
        // 	let mut read_packet: mdns_packet = Default::default();
        let mut byte_array = [0u8; 65536];

        let (amt, src) = udp_socket.recv_from(&mut byte_array).unwrap();
        // println!("{:?} {:?}", amt, src);

        let mdns_data = parse_packet(&byte_array[0..amt]);
        debug!("{:?}", mdns_data);
    }
}
