pub mod bip;
pub mod crypto;
pub mod derivation;
#[macro_use]
pub(crate) mod internal_macros;
pub mod keys;
pub mod network;
pub mod util;

use crate::network::DevnetType;
use crate::util::data_append::DataAppend;

#[ferment_macro::export]
pub fn x11(data: &[u8]) -> [u8; 32] {
    rs_x11_hash::get_x11_hash(data)
}

#[ferment_macro::export]
pub fn blake3(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}
#[ferment_macro::export]
pub fn devnet_genesis_coinbase_message(devnet_type: DevnetType, protocol_version: u32) -> Vec<u8> {
    Vec::<u8>::devnet_genesis_coinbase_message(devnet_type, protocol_version)
}

#[cfg(test)]
mod tests {
    use dashcore::hashes::hex::FromHex;
    use dashcore::prelude::DisplayHex;

    #[test]
    fn test_blake3() {
        let md = blake3::hash("".as_bytes());
        assert_eq!(md.to_hex().as_str(), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "blake 3 err");
    }

    #[test]
    fn test_x11() {
        let x11 = "020000002cc0081be5039a54b686d24d5d8747ee9770d9973ec1ace02e5c0500000000008d7139724b11c52995db4370284c998b9114154b120ad3486f1a360a1d4253d310d40e55b8f70a1be8e32300";
        let input = Vec::from_hex(x11).unwrap();
        let output = rs_x11_hash::get_x11_hash(input);
        assert_eq!("f29c0f286fd8071669286c6987eb941181134ff5f3978bf89f34070000000000", output.to_lower_hex_string(), "x11 error");

        let x11 = "040000002e3df23eec5cd6a86edd509539028e2c3a3dc05315eb28f2baa43218ca080000b3a56d65316ffdb006163240a4380e94a4c2d8c0f0b3b2c1ddc486fae15ed065ba968054ffff7f2000000000";
        let input = Vec::from_hex(x11).unwrap();
        let output = rs_x11_hash::get_x11_hash(input);
        assert_eq!("2990cb88c53c588b58188f6868972ec37e955903940ab7604da44c3291204cce", output.to_lower_hex_string(), "x11 error");

        let x11 = "040000002e3df23eec5cd6a86edd509539028e2c3a3dc05315eb28f2baa43218ca080000b3a56d65316ffdb006163240a4380e94a4c2d8c0f0b3b2c1ddc486fae15ed065ba968054ffff7f2001000000";
        let input = Vec::from_hex(x11).unwrap();
        let output = rs_x11_hash::get_x11_hash(input);
        assert_eq!("412a340f4a1442b42f703523f2c5c041d5eed7dfad6bd7eda16b8d55e575f7df", output.to_lower_hex_string(), "x11 error");

        let x11 = "040000002e3df23eec5cd6a86edd509539028e2c3a3dc05315eb28f2baa43218ca080000b3a56d65316ffdb006163240a4380e94a4c2d8c0f0b3b2c1ddc486fae15ed065ba968054ffff7f2002000000";
        let input = Vec::from_hex(x11).unwrap();
        let output = rs_x11_hash::get_x11_hash(input);
        assert_eq!("000739d9da507b3acb949f21fe10ad424abbad5b4c46789285b05fe36df5c5b0", output.to_lower_hex_string(), "x11 error");

        let x11 = "040000002e3df23eec5cd6a86edd509539028e2c3a3dc05315eb28f2baa43218ca080000b3a56d65316ffdb006163240a4380e94a4c2d8c0f0b3b2c1ddc486fae15ed065ba968054ffff7f2003000000";
        let input = Vec::from_hex(x11).unwrap();
        let output = rs_x11_hash::get_x11_hash(input);
        assert_eq!("90ec0543cd91297e7ad3d3141a404fb55f787b3058aca2b45ab0fc20d06409c6", output.to_lower_hex_string(), "x11 error");

        let x11 = "040000002e3df23eec5cd6a86edd509539028e2c3a3dc05315eb28f2baa43218ca080000b3a56d65316ffdb006163240a4380e94a4c2d8c0f0b3b2c1ddc486fae15ed065ba968054ffff7f2004000000";
        let input = Vec::from_hex(x11).unwrap();
        let output = rs_x11_hash::get_x11_hash(input);
        assert_eq!("eee8ff78056e3b0cd35cd8e267fa871270a183a5d05c764d8c2047b7c3cca014", output.to_lower_hex_string(), "x11 error");
    }
}

