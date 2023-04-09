#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(non_snake_case)]

use std::borrow::Cow;
use std::io::{Cursor, Read, Write};
use std::ptr::write;
use std::rc::Rc;
use std::string::FromUtf8Error;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use mysql::*;
use mysql::BinlogStream;
use mysql::prelude::*;
use mysql_common::binlog::BinlogStruct;
use mysql_common::constants::{CapabilityFlags, StatusFlags};
use mysql_common::frunk::labelled::chars::T;
use mysql_common::packets::{ComBinlogDump, HandshakePacket};
use wasmedge_wasi_socket::*;
use mysql_common::scramble::scramble_sha256;

fn read_zero_terminated_string(cursor: &mut Cursor<Vec<u8>>) -> Vec<u8> {
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

fn receive_greeting(stream:&mut TcpStream) -> HandshakePacket{

    let mut packet = vec![0; 95];
    stream.read(&mut packet).unwrap();

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

fn authenticate(stream: &mut TcpStream){

}

fn main() -> std::io::Result<()> {
    let mut stream =TcpStream::connect("127.0.0.1:3306")?;

    println!("Listening to port 3306");

    // ==========================================================================================================

    let handshake_packet = receive_greeting(&mut stream);

    // ==========================================================================================================

    Ok(())
}
