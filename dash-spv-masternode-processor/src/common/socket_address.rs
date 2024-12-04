use std::io;
use byte::{BytesExt, TryRead};
use hashes::hex::ToHex;
use dash_spv_crypto::consensus::{Decodable, Encodable, encode};
use dash_spv_crypto::crypto::byte_util::clone_into_array;
use dash_spv_crypto::crypto::UInt128;

#[repr(C)]
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq)]
#[ferment_macro::export]
pub struct SocketAddress {
    pub ip_address: [u8; 16], //v6, but only v4 supported
    pub port: u16,
}

#[ferment_macro::export]
impl SocketAddress {
    pub fn ipv4(&self) -> u32 {
        u32::from_be_bytes(clone_into_array(&self.ip_address[12..]))
    }
}

impl std::fmt::Display for SocketAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}", self.ip_address.to_hex(), self.port)?;
        Ok(())
    }
}

impl Encodable for SocketAddress {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        self.ip_address.enc(&mut s);
        self.port.swap_bytes().enc(&mut s);
        Ok(18)
    }
}

impl Decodable for SocketAddress {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let ip_address = <[u8; 16]>::consensus_decode(&mut d)?;
        let port = u16::consensus_decode(&mut d)?;
        Ok(Self { ip_address, port })
    }
}


impl<'a> TryRead<'a, ()> for SocketAddress {
    fn try_read(bytes: &'a [u8], context: ()) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let ip_address = bytes.read_with::<UInt128>(offset, byte::LE)?.0;
        let port = bytes.read_with::<u16>(offset, byte::BE)?;
        Ok((SocketAddress { ip_address, port }, *offset))
    }
}
