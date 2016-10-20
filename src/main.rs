// disable warnings for dead code when running debug
#![cfg_attr(debug_assertions, allow(dead_code))]

extern crate net2;
extern crate bincode;
extern crate rustc_serialize;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate byteorder;

use std::net::Ipv4Addr;
#[cfg(not(windows))]
use net2::unix::UnixUdpBuilderExt;
use net2::UdpBuilder;
use bincode::rustc_serialize::decode;
use byteorder::{ByteOrder, NetworkEndian};

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

#[derive(Debug)]
enum MDNSType {
    A,
    PTR,
    TXT(Vec<String>),
    AAAA,
    SRV,
    NSEC,
    ANY,
    UNKNOW(u16),
}

impl MDNSType {
    #[doc(hidden)]
    pub fn from_u16(n: u16) -> MDNSType {
        match n {
            0x01 => MDNSType::A,
            0x0C => MDNSType::PTR,
            0x10 => MDNSType::TXT(vec![]),
            0x1C => MDNSType::AAAA,
            0x21 => MDNSType::SRV,
            0x2F => MDNSType::NSEC,
            0xFF => MDNSType::ANY,
            _ => MDNSType::UNKNOW(n),
        }
    }

    #[doc(hidden)]
    pub fn to_u16(&self) -> u16 {
        match *self {
            MDNSType::A => 0x01,
            MDNSType::PTR => 0x0C,
            MDNSType::TXT(_) => 0x10,
            MDNSType::AAAA => 0x1C,
            MDNSType::SRV => 0x21,
            MDNSType::NSEC => 0x2F,
            MDNSType::ANY => 0xFF,
            MDNSType::UNKNOW(n) => n,
        }
    }

    pub fn from_data(mdns_type_id: u16, packet_data: &[u8]) -> MDNSType {
        match MDNSType::from_u16(mdns_type_id) {
            MDNSType::TXT(_) => {
                let mut txt_map = vec![];
                let mut data_offset: usize = 0;
                while packet_data.len() > data_offset {
                    let (label_string, label_size) = label_to_string(packet_data, data_offset);
                    trace!("TXT: {} {}", label_string, label_size);
                    txt_map.push(label_string);
                    data_offset += label_size;
                }
                trace!("{:?}", txt_map);
                MDNSType::TXT(txt_map)
            }
            _ => MDNSType::UNKNOW(mdns_type_id),
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
    rr_class: u16,
}

#[derive(Debug)]
struct MDNSAnswer {
    name: String,
    rr_type: MDNSType,
    rr_class: u16,
    ttl: u32,
}

#[inline]
fn label_to_string(packet: &[u8], offset: usize) -> (String, usize) {
    let string_size = packet[offset] as usize;

    let full_string = String::from_utf8_lossy(&packet[(offset + 1)..(offset + 1 + string_size)])
        .into_owned();

    (full_string, string_size + 1)
}

fn decompress_label(packet: &[u8], mut offset: usize) -> (String, usize) {
    // create the string
    let mut full_string = String::new();
    // second offset to let the caller know how much we moved
    // from the current offset
    let mut label_offset = 0;

    // helper that gets true as soon as we have hit a compress token
    // the label_offset calculation is different when we have have
    // a commpressed label
    let mut compressed = false;

    // Now go until we found a string with ZERO length
    while 0 != packet[offset] {
        // if this is not the first string we have found,
        // add a . to join them
        if full_string.len() > 0 {
            full_string.push('.');
        }

        trace!("size buffer: {:?}", &packet[offset..(offset + 2)]);

        // is this a compressed token?
        if 0xC0 == (packet[offset] & 0xC0) {
            // yes
            if false == compressed {
                compressed = true;
                // we have moved 2 bytes from the current position in memory
                label_offset += 2;
            }

            // now the second byte after the token
            // is the lower size of the uint16 offset
            // from the packet start!!!
            let small_size = packet[offset + 1] as usize;
            trace!("In BIG SIZE: {}", small_size);

            // get the higher size
            offset = (packet[offset] & 0x3F) as usize;
            trace!("In BIG SIZE_1: {}", offset);

            // shift 8 bits to the left
            offset *= 256;
            trace!("In BIG SIZE_2: {}", offset);

            // add the lower part
            offset += small_size;
        }

        // get size of the string
        let string_size = packet[offset] as usize;
        // jump over the size byte
        offset += 1;

        trace!("Before UTF8_2: {} {}", offset, string_size);
        trace!("Before UTF8: {:?}", &packet[offset..(offset + string_size)]);

        // now convert the bytes to a string
        // TODO: UTF8???? Or ASCII?
        full_string += std::str::from_utf8(&packet[offset..(offset + string_size)]).unwrap();

        // move to the next token
        offset += string_size;

        if false == compressed {
            // if we haven't had a compress token yet
            // just a the size byte and the string length
            label_offset += string_size;
            label_offset += 1;
        }
    }

    // skip the last ZERO byte indicating the end of the string
    if false == compressed {
        // but only if we have NO compressed string
        label_offset += 1;
    }

    trace!("{:?} {}", full_string, label_offset);

    // done, return the string and the offset we moved
    // in memory to get the String
    (full_string, label_offset)
}

fn parse_packet(packet: &[u8]) -> Result<MDNSData, String> {
    let decoded: MDNSPacketHeader = try!(decode(&packet[0..12]).map_err(|e| e.to_string()));

    let mut result = MDNSData {
        id: decoded.id,
        flags: decoded.flags,
        questions: vec![],
        answers: vec![],
    };

    let mut decode_position = std::mem::size_of::<MDNSPacketHeader>();

    // parse the questions
    for _ in 0..decoded.num_qn {
        // first read the label
        let (label_string, label_offset) = decompress_label(packet, decode_position);
        // move the offset
        decode_position += label_offset;

        // now read the uint16 type
        let rr_type = NetworkEndian::read_u16(&packet[decode_position..(decode_position + 2)]);
        decode_position += 2;
        // and the class (uint16)
        let class_type = NetworkEndian::read_u16(&packet[decode_position..(decode_position + 2)]);
        decode_position += 2;

        // Add the create and push the question struct
        result.questions.push(MDNSQuestion {
            name: label_string,
            rr_type: MDNSType::from_u16(rr_type),
            rr_class: class_type,
        });
    }

    for _ in 0..decoded.num_ans_rr {
        // first read the label
        let (label_string, label_offset) = decompress_label(packet, decode_position);
        // move the offset
        decode_position += label_offset;

        // now read the uint16 type
        let rr_type = NetworkEndian::read_u16(&packet[decode_position..(decode_position + 2)]);
        decode_position += 2;
        // and the class (uint16)
        let class_type = NetworkEndian::read_u16(&packet[decode_position..(decode_position + 2)]);
        decode_position += 2;

        let ttl = NetworkEndian::read_u32(&packet[decode_position..(decode_position + 4)]);
        decode_position += 4;

        // RR data
        let data_len =
            NetworkEndian::read_u16(&packet[decode_position..(decode_position + 2)]) as usize;
        decode_position += 2;

        trace!("Data len: {}, type: {:?}",
               data_len,
               MDNSType::from_u16(rr_type));

        // Add the create and push the question struct
        result.answers.push(MDNSAnswer {
            name: label_string,
            rr_type: MDNSType::from_data(rr_type,
                                         &packet[decode_position..(decode_position + data_len)]),
            rr_class: class_type,
            ttl: ttl,
        });

        decode_position += data_len;

    }

    debug!("{:?}", decoded);

    Ok(result)
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

        let (amt, _) = udp_socket.recv_from(&mut byte_array).unwrap();
        // println!("{:?} {:?}", amt, src);

        if let Ok(mdns_data) = parse_packet(&byte_array[0..amt]) {
            debug!("{:?}", mdns_data);
        }
    }
}
