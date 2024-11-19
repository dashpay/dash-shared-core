pub mod addresses {
    use dash_spv_crypto::crypto::byte_util::UInt160;
    use dash_spv_crypto::network::ChainType;
    use dash_spv_crypto::util::address::address;
    use dash_spv_crypto::util::data_append::DataAppend;

    #[ferment_macro::export]
    pub fn address_from_hash160(hash: UInt160, chain_type: ChainType) -> String {
        let script_map = chain_type.script_map();
        address::from_hash160_for_script_map(&hash, &script_map)
    }

    #[ferment_macro::export]
    pub fn address_with_script_pubkey(script: Vec<u8>, chain_type: ChainType) -> Option<String> {
        address::with_script_pub_key(&script, &chain_type.script_map())
    }

    #[ferment_macro::export]
    pub fn address_with_script_sig(script: Vec<u8>, chain_type: ChainType) -> Option<String> {
        address::with_script_sig(&script, &chain_type.script_map())
    }

    #[ferment_macro::export]
    pub fn script_pubkey_for_address(address: Option<String>, chain_type: ChainType) -> Option<Vec<u8>> {
        address.map(|address| DataAppend::script_pub_key_for_address(address.as_str(), &chain_type.script_map()))
    }

    #[ferment_macro::export]
    pub fn is_valid_dash_address_for_chain(address: Option<String>, chain_type: ChainType) -> bool {
        address.map_or(false, |address| address::is_valid_dash_address_for_script_map(address.as_str(), &chain_type.script_map()))
    }
}
