use std::io::{BufRead, BufReader, BufWriter, Write};
use byteorder::{LittleEndian, WriteBytesExt};
use wasmedge_wasi_socket::*;

pub struct PacketChannel<'a>{
    reader: BufReader<&'a TcpStream>,
    writer: BufWriter<&'a TcpStream>,
    packet_number: u8,
    authentication_complete: bool,
    is_ssl: bool
}

impl<'a> PacketChannel<'a> {

    pub fn new(stream:  &'a TcpStream) -> Self {
        PacketChannel{
            reader: BufReader::new(stream),
            writer: BufWriter::new(stream),
            packet_number: 0,
            authentication_complete: false,
            is_ssl: false
        }
    }

    pub fn read(&mut self) -> Vec<u8> {
        let mut packet = self.reader.fill_buf().unwrap().to_vec();
        if self.packet_number != packet[3] {
           unimplemented!("Invalid sequence of packet");
        }
        self.packet_number +=1;
        packet[4..].to_vec()
    }

    pub fn write(&mut self,body: Vec<u8>) {
        let mut packet = vec![];
        packet.write_u24::<LittleEndian>(body.len() as u32).unwrap();

        // Only need to maintain packet_number in auth phase.
        if self.authentication_complete {
            self.packet_number = 0;
        }

        packet.write_u8(self.packet_number).unwrap();
        self.packet_number += 1;
        packet.write_all(&*body);
        self.writer.write_all(&*packet).unwrap();
    }

    pub fn authentication_complete(&mut self) {
        self.authentication_complete = true;
    }

    pub fn enable_ssl(&mut self) {
        self.is_ssl = true;
    }
}