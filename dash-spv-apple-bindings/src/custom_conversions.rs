#[allow(non_camel_case_types)]
#[ferment_macro::register(std::net::SocketAddr)]
#[derive(Clone)]
pub enum SocketAddr {
    V4 { ip: *mut [u8; 4], port: u16 },
    V6 { ip: *mut [u8; 16], port: u16, flowinfo: u32, scope_id: u32 },
}
impl ferment_interfaces::FFIConversion<std::net::SocketAddr> for SocketAddr {
    unsafe fn ffi_from_const(ffi: *const Self) -> std::net::SocketAddr {
        let ffi = &*ffi;
        match ffi {
            Self::V4 { ip, port } =>
                std::net::SocketAddr::V4(std::net::SocketAddrV4::new(std::net::Ipv4Addr::from(*ip.clone()), *port)),
            Self::V6 { ip, port, flowinfo, scope_id } =>
                std::net::SocketAddr::V6(std::net::SocketAddrV6::new(std::net::Ipv6Addr::from(*ip.clone()), *port, *flowinfo, *scope_id))
        }
    }
    unsafe fn ffi_to_const(obj: std::net::SocketAddr) -> *const Self {
        ferment_interfaces::boxed(match obj {
            std::net::SocketAddr::V4(addr) =>
                Self::V4 { ip: ferment_interfaces::boxed(addr.ip().octets()), port: addr.port() },
            std::net::SocketAddr::V6(addr) =>
                Self::V6 { ip: ferment_interfaces::boxed(addr.ip().octets()), port: addr.port(), flowinfo: addr.flowinfo(), scope_id: addr.scope_id() }
        })
    }
}

impl Drop for SocketAddr {
    fn drop(&mut self) {
        unsafe {
            match self {
                Self::V4 { ip, port } => { ferment_interfaces::unbox_any(ip); }
                Self::V6 { ip, port, flowinfo, scope_id } => { ferment_interfaces::unbox_any(ip); }
            }
        }
    }
}
