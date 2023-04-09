#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(non_snake_case)]

use std::borrow::Cow;
use std::io::{BufRead, BufReader, BufWriter, Cursor, Read, Write};
use std::ptr::write;
use std::rc::Rc;
use std::string::FromUtf8Error;
use std::sync::Mutex;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use mysql_common::binlog::BinlogStruct;
use mysql_common::constants::{CapabilityFlags, StatusFlags};
use mysql_common::frunk::labelled::chars::T;
use wasmedge_wasi_socket::*;
use mysql_common::packets::{AuthPlugin, ComBinlogDump, HandshakePacket, HandshakeResponse};
use mysql_common::scramble::{scramble_native, scramble_sha256};

mod packetChannel;

fn read_zero_terminated_string(cursor: &mut Cursor<&Vec<u8>>) -> Vec<u8> {
    let mut bytes = vec![];

    loop {
       let byte = cursor.read_u8().unwrap();

        if byte == 0 {break;}

        bytes.push(byte);
    }

    bytes
}

fn write_zero_terminated_string(string: String) -> Vec<u8>{
    let mut bytes = string.into_bytes();
    bytes.write_u8(0).unwrap();
    bytes
}

fn receive_greeting(packet:&Vec<u8>) -> HandshakePacket{

    let mut cursor = Cursor::new(packet);

    let packet_length = cursor.read_u24::<LittleEndian>().unwrap();
    let packet_number = cursor.read_u8().unwrap();
    let protocol_version = cursor.read_u8().unwrap();
    let server_version = read_zero_terminated_string(&mut cursor);
    let thread_id = cursor.read_u32::<LittleEndian>().unwrap();
    let scramble_1 = read_zero_terminated_string(&mut cursor);
    let server_capabilities = CapabilityFlags::from_bits(cursor.read_u16::<LittleEndian>().unwrap() as u32).unwrap();
    let server_collation = cursor.read_u8().unwrap();
    let server_status = StatusFlags::from_bits(cursor.read_u16::<LittleEndian>().unwrap()).unwrap();
    cursor.set_position(cursor.position() + 13); // Reserved bytes
    let mut scramble_2 = read_zero_terminated_string(&mut cursor);

    let mut plugin_provided_data = vec![];
    if packet_length > cursor.position() as u32 {
        plugin_provided_data = read_zero_terminated_string(&mut cursor);
    };

    // Check support for maira db
    HandshakePacket::new(
        protocol_version,
        Cow::from(server_version),
        thread_id,
        <[u8; 8]>::try_from(scramble_1.as_slice()).unwrap(),
        Some(Cow::from(scramble_2)),
        server_capabilities,
        server_collation,
        server_status,
        Some(Cow::from(plugin_provided_data))
    )
}

fn caching_sha2_password(handshake_packet:&HandshakePacket) -> Vec<u8>{

    let mut capability_bits;
    capability_bits = (CapabilityFlags::CLIENT_LONG_FLAG |
        CapabilityFlags::CLIENT_PROTOCOL_41 |
        CapabilityFlags::CLIENT_SECURE_CONNECTION |
        CapabilityFlags::CLIENT_PLUGIN_AUTH |
        CapabilityFlags::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA);

    let mut body = vec![];

    body.write_u32::<LittleEndian>(capability_bits.bits()).unwrap();
    body.write_u32::<LittleEndian>(0).unwrap();
    body.write_u8(handshake_packet.default_collation()).unwrap();
    body.write_all(&[0 as u8;23]).unwrap(); // reserved
    body.write_all(&*write_zero_terminated_string(String::from("root"))).unwrap();

    let password_bytes = "Hrushi20".as_bytes();
    let password = scramble_sha256(&*handshake_packet.nonce(), password_bytes).unwrap();
    body.write_u8(password.len() as u8).unwrap();
    body.write_all(&password).unwrap();
    body.write_all(handshake_packet.auth_plugin_name_ref().unwrap()).unwrap();

    body

}

fn mysql_native_password(handshake_packet:&HandshakePacket) -> Vec<u8>{

    let mut capability_bits;
    capability_bits = (CapabilityFlags::CLIENT_LONG_FLAG |
        CapabilityFlags::CLIENT_PROTOCOL_41 |
        CapabilityFlags::CLIENT_SECURE_CONNECTION |
        CapabilityFlags::CLIENT_PLUGIN_AUTH);


    let mut body = vec![];
    body.write_u32::<LittleEndian>(capability_bits.bits()).unwrap();
    body.write_u32::<LittleEndian>(0).unwrap();
    body.write_u8(handshake_packet.default_collation()).unwrap();
    body.write_all(&[0 as u8;23]).unwrap(); // reserved
    body.write_all(&*write_zero_terminated_string(String::from("root"))).unwrap();
    // get sha1 password;
    let password_bytes = "Hrushi20".as_bytes();
    let password = scramble_native(&*handshake_packet.nonce(), password_bytes).unwrap();
    body.write_u8(password.len() as u8).unwrap();
    body.write_all(&password).unwrap();
    body.write_all(handshake_packet.auth_plugin_name_ref().unwrap());

    body
}

fn authenticate(handshake_packet: &HandshakePacket) -> Vec<u8> {

    match handshake_packet.auth_plugin() {
        Some(AuthPlugin::CachingSha2Password) => caching_sha2_password(&handshake_packet),
        Some(AuthPlugin::MysqlNativePassword) => mysql_native_password(&handshake_packet),
        _ => vec![],
    }
}

fn main() -> Result<(),()> {
    let mut stream = TcpStream::connect("127.0.0.1:3306").unwrap();

    println!("Listening to port 3306");

    // ==========================================================================================================
    let mut channel = packetChannel::PacketChannel::new(&mut stream);

    let greeting_body = channel.read();
    let handshake_packet = receive_greeting(&greeting_body);

     // ==========================================================================================================
    let mut auth_bytes = authenticate(&handshake_packet);
    channel.write(auth_bytes);

    let auth_response = channel.read();

    match auth_response[0] {
        0x00 => true, // Success in authentication,
        0xFF => unimplemented!("Authentication Error"),
        0xFE => unimplemented!("Need to switch Authentication"),
        _ => unimplemented!("Need to process caching sha2 result or switch authentication")
    };

    channel.authentication_complete();
    println!("Authenticated my sql db successfully.");


    Ok(())
}
