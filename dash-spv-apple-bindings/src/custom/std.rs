use std::net::{Ipv4Addr, Ipv6Addr};
use ferment::{boxed, FFIConversionDestroy, FFIConversionFrom, FFIConversionTo};
use crate::fermented::generics::{Arr_u8_16, Arr_u8_4};

#[allow(non_camel_case_types)]
#[ferment_macro::register(std::net::SocketAddr)]
#[derive(Clone)]
pub enum SocketAddr {
    V4 { ip: *mut Arr_u8_4, port: u16 },
    V6 { ip: *mut Arr_u8_16, port: u16, flowinfo: u32, scope_id: u32 },
}

impl FFIConversionFrom<std::net::SocketAddr> for SocketAddr {
    unsafe fn ffi_from_const(ffi: *const Self) -> std::net::SocketAddr {
        let ffi = &*ffi;
        match ffi {
            Self::V4 { ip, port } => {
                let octets = FFIConversionFrom::<[u8; 4]>::ffi_from_const(*ip);
                std::net::SocketAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::from(octets), *port))
            },
            Self::V6 { ip, port, flowinfo, scope_id } => {
                let octets = FFIConversionFrom::<[u8; 16]>::ffi_from_const(*ip);
                std::net::SocketAddr::V6(std::net::SocketAddrV6::new(Ipv6Addr::from(octets), *port, *flowinfo, *scope_id))
            }
        }
    }
}

impl FFIConversionTo<std::net::SocketAddr> for SocketAddr {
    unsafe fn ffi_to_const(obj: std::net::SocketAddr) -> *const Self {
        boxed(match obj {
            std::net::SocketAddr::V4(addr) => {
                let octets = addr.ip().octets();
                Self::V4 { ip: FFIConversionTo::ffi_to(octets), port: addr.port() }
            },
            std::net::SocketAddr::V6(addr) => {
                let octets = addr.ip().octets();
                Self::V6 { ip: FFIConversionTo::ffi_to(octets), port: addr.port(), flowinfo: addr.flowinfo(), scope_id: addr.scope_id() }
            }
        })
    }
}

impl FFIConversionDestroy<std::net::SocketAddr> for SocketAddr {}

impl Drop for SocketAddr {
    fn drop(&mut self) {
        unsafe {
            match self {
                Self::V4 { ip, port } => {
                    ferment::unbox_any(*ip);
                }
                Self::V6 { ip, port, flowinfo, scope_id } => {
                    ferment::unbox_any(*ip);
                }
            }
        }
    }
}
