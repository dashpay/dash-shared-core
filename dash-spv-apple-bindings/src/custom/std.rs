use ferment::{boxed, from_primitive_group, FFIConversionFrom, FFIConversionTo};
use crate::fermented::generics::{Arr_u8_16, Arr_u8_4};

#[allow(non_camel_case_types)]
#[ferment_macro::register(std::net::SocketAddr)]
#[derive(Clone)]
pub enum SocketAddr {
    V4 { ip: *mut Arr_u8_4, port: u16 },
    V6 { ip: *mut Arr_u8_16, port: u16, flowinfo: u32, scope_id: u32 },
}
impl FFIConversionFrom<std::net::Ipv4Addr> for Arr_u8_4  {
    unsafe fn ffi_from_const(ffi: *const Self) -> std::net::Ipv4Addr {
        let ffi_ref = &*ffi;
        let vec: Vec<u8> = from_primitive_group(ffi_ref.values, ffi_ref.count);
        let octets: [u8; 4] = vec.try_into().unwrap();
        std::net::Ipv4Addr::from(octets)
    }
}
impl FFIConversionTo<std::net::Ipv4Addr> for Arr_u8_4  {
    unsafe fn ffi_to_const(obj: std::net::Ipv4Addr) -> *const Self {
        boxed(Self { count: 4, values: ferment::to_primitive_group(obj.octets().into_iter ()) })
    }
}
impl FFIConversionFrom<std::net::Ipv6Addr> for Arr_u8_16  {
    unsafe fn ffi_from_const(ffi: *const Self) -> std::net::Ipv6Addr {
        let ffi_ref = &*ffi;
        let vec: Vec<u8> = from_primitive_group(ffi_ref.values, ffi_ref.count);
        let octets: [u8; 16] = vec.try_into().unwrap();
        std::net::Ipv6Addr::from(octets)
    }
}
impl FFIConversionTo<std::net::Ipv6Addr> for Arr_u8_16  {
    unsafe fn ffi_to_const(obj: std::net::Ipv6Addr) -> *const Self {
        boxed(Self { count: 16, values: ferment::to_primitive_group(obj.octets().into_iter()) })
    }
}

impl FFIConversionFrom<std::net::SocketAddr> for SocketAddr {
    unsafe fn ffi_from_const(ffi: *const Self) -> std::net::SocketAddr {
        let ffi = &*ffi;
        match ffi {
            Self::V4 { ip, port } =>
                std::net::SocketAddr::V4(std::net::SocketAddrV4::new(FFIConversionFrom::ffi_from(*ip), *port)),
            Self::V6 { ip, port, flowinfo, scope_id } =>
                std::net::SocketAddr::V6(std::net::SocketAddrV6::new(FFIConversionFrom::ffi_from(*ip), *port, *flowinfo, *scope_id))
        }
    }
}

impl FFIConversionTo<std::net::SocketAddr> for SocketAddr {
    unsafe fn ffi_to_const(obj: std::net::SocketAddr) -> *const Self {
        boxed(match obj {
            std::net::SocketAddr::V4(addr) =>
                Self::V4 { ip: FFIConversionTo::ffi_to(addr.ip().octets()), port: addr.port() },
            std::net::SocketAddr::V6(addr) =>
                Self::V6 { ip: FFIConversionTo::ffi_to(addr.ip().octets()), port: addr.port(), flowinfo: addr.flowinfo(), scope_id: addr.scope_id() }
        })
    }
}

impl Drop for SocketAddr {
    fn drop(&mut self) {
        unsafe {
            match self {
                Self::V4 { ip, port } => {
                    ferment::unbox_any(ip);
                }
                Self::V6 { ip, port, flowinfo, scope_id } => {
                    ferment::unbox_any(ip);
                }
            }
        }
    }
}
