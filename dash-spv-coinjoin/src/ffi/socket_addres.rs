#[repr(C)]
#[derive(Clone, Debug)]
pub struct SocketAddress {
    pub ip_address: *mut [u8; 16],
    pub port: u16
}
