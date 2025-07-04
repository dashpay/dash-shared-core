use hashes::{Hash, sha256d};
use crate::blockdata::opcodes::all::{OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4, OP_RETURN};
use crate::chain::common::chain_type::DevnetType;
use crate::chain::params::{BITCOIN_SCRIPT_ADDRESS, ScriptMap};
use crate::consensus::{Encodable, WriteExt};
use crate::util::base58;
use crate::util::script::{op_len, ScriptElement};

pub trait DataAppend: std::io::Write {
    fn from_coinbase_message(message: &String, height: u32) -> Self;
    fn devnet_genesis_coinbase_message(devnet_type: DevnetType, protocol_version: u32) -> Self;
    fn script_pub_key_for_address(address: &str, script_map: &ScriptMap) -> Self;
    fn credit_burn_script_pub_key_for_address(address: &String, script_map: &ScriptMap) -> Self;
    fn proposal_info(proposal_info: Vec<u8>) -> Self;
    fn shapeshift_memo_for_address(address: String) -> Self;

    fn append_coinbase_message<W: std::io::Write>(&self, message: &String, height: u32, writer: W) -> W;
    fn append_devnet_genesis_coinbase_message(devnet_type: DevnetType, protocol_version: u32, writer: Self) -> Self;
    fn append_credit_burn_script_pub_key_for_address(address: &String, script_map: &ScriptMap, writer: Self) -> Self;
    fn append_proposal_info(proposal_info: &Vec<u8>, writer: Self) -> Self;
    fn append_script_pub_key_for_address(address: &str, script_map: &ScriptMap, writer: Self) -> Self;
    fn append_script_push_data<W: std::io::Write>(&self, writer: W);
    // fn append_script_push_data(&mut self, data: Vec<u8>);
    fn append_shapeshift_memo_for_address(address: String, writer: Self) -> Self;
    // fn append_string(&mut self, data: String);

    fn script_elements(&self) -> Vec<ScriptElement>;
}


const U16MAX: u32 = u16::MAX as u32;
const U16MAX_PLUS_1: u32 = U16MAX + 1;

impl DataAppend for Vec<u8> /* io::Write */ {

    fn from_coinbase_message(message: &String, height: u32) -> Self {
        Vec::<u8>::new().append_coinbase_message(message, height, Vec::<u8>::new())
        // Self::append_coinbase_message(message, height, Vec::<u8>::new())
    }

    fn devnet_genesis_coinbase_message(devnet_type: DevnetType, protocol_version: u32) -> Self {
        Self::append_devnet_genesis_coinbase_message(devnet_type, protocol_version, Vec::<u8>::new())
    }

    fn script_pub_key_for_address(address: &str, script_map: &ScriptMap) -> Self {
        Self::append_script_pub_key_for_address(address, script_map, Vec::<u8>::new())
    }

    fn credit_burn_script_pub_key_for_address(address: &String, script_map: &ScriptMap) -> Self {
        Self::append_credit_burn_script_pub_key_for_address(address, script_map, Vec::<u8>::new())
    }

    fn proposal_info(proposal_info: Vec<u8>) -> Self {
        Self::append_proposal_info(&proposal_info, Vec::<u8>::new())
    }

    fn shapeshift_memo_for_address(address: String) -> Self {
        Self::append_shapeshift_memo_for_address(address, Vec::<u8>::new())
    }

    // fn append_coinbase_message<W: std::io::Write>(message: &String, height: u32, mut writer: W) {
    fn append_coinbase_message<W: std::io::Write>(&self, message: &String, height: u32, mut writer: W) -> W {

        // }
        // fn append_coinbase_message(message: &String, height: u32, mut writer: Self) -> Self {
        // todo: check
        //NSUInteger l = [message lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
        let l = message.len();
        match height {
            0..=0xfc => {
                let header = l as u8;
                let payload = height as u8;
                header.enc(&mut writer);
                payload.enc(&mut writer);
            },
            0xfd..=U16MAX => {
                let header = (0xfd + l) as u8;
                let payload = (height as u16).swap_bytes();
                header.enc(&mut writer);
                payload.enc(&mut writer);
            },
            U16MAX_PLUS_1..=u32::MAX => {
                let header = (0xfe + l) as u8;
                let payload = height.swap_bytes();
                header.enc(&mut writer);
                payload.enc(&mut writer);
            }
        }
        message.enc(&mut writer);
        writer
    }

    fn append_devnet_genesis_coinbase_message(devnet_type: DevnetType, protocol_version: u32, mut writer: Self) -> Self {
        // A little weirder
        0x51u8.enc(&mut writer);
        let identifier = devnet_type.identifier();
        let bytes = identifier.as_bytes();
        let len: u8 = bytes.len() as u8;
        len.enc(&mut writer);
        writer.emit_slice(bytes).unwrap();
        //if protocol_version >= 70221 {
        //  [self appendUInt8:version + 0x50];
        //}
        writer
    }

    fn append_credit_burn_script_pub_key_for_address(address: &String, script_map: &ScriptMap, mut writer: Self) -> Self {
        // todo: check impl base58checkToData
        match base58::from_check(address.as_str()) {
            Ok(d) if d.len() == 21 => {
                OP_RETURN.into_u8().enc(&mut writer);
                // d[1..].to_vec().append_script_push_data(&mut writer);
                // writer.append_script_push_data(d[1..].to_vec());
                d[1..].to_vec().append_script_push_data(&mut writer);
                writer
            },
            _ => panic!("append_credit_burn_script_pub_key_for_address: base58::from_check error")
        }
    }

    fn append_proposal_info(proposal_info: &Vec<u8>, mut writer: Self) -> Self {
        let hash = sha256d::Hash::hash(proposal_info).into_inner();
        OP_RETURN.into_u8().enc(&mut writer);
        // TODO check we need to write varint
        hash.to_vec().enc(&mut writer);
        // writer.append_script_push_data(hash.to_vec());
        // hash.to_vec().append_script_push_data(&mut writer);
        writer
    }

    fn append_script_pub_key_for_address(address: &str, script_map: &ScriptMap, mut writer: Self) -> Self {
        match base58::from_check(address) {
            Ok(data) => match &data[..] {
                [v, data @ ..] if *v == script_map.pubkey => {
                    OP_DUP.into_u8().enc(&mut writer);
                    OP_HASH160.into_u8().enc(&mut writer);
                    data.to_vec().append_script_push_data(&mut writer);
                    OP_EQUALVERIFY.into_u8().enc(&mut writer);
                    OP_CHECKSIG.into_u8().enc(&mut writer);
                },
                [v, data @ ..] if *v == script_map.script => {
                    OP_HASH160.into_u8().enc(&mut writer);
                    data.to_vec().append_script_push_data(&mut writer);
                    OP_EQUAL.into_u8().enc(&mut writer);
                },
                _ => {}
            },
            _ => panic!("append_script_pub_key_for_address: base58::from_check error")
        }
        writer
    }

    // fn append_script_push_data(&mut self, data: Vec<u8>) {
    //     let len = data.len();
    //     match len {
    //         0 => { return },
    //         1..=0x4b => {
    //             (len as u8).enc(self);
    //         }
    //         0x4c..=0xffff => {
    //             OP_PUSHDATA1.into_u8().enc(self);
    //             (len as u8).enc(self);
    //         },
    //         0x10000..=0xffffffff => {
    //             OP_PUSHDATA2.into_u8().enc(self);
    //             (len as u16).enc(self);
    //         },
    //         _ => {
    //             OP_PUSHDATA4.into_u8().enc(self);
    //             (len as u32).enc(self);
    //         },
    //     }
    //     self.extend(data);
    // }
    fn append_script_push_data<W: std::io::Write>(&self, mut writer: W) {
        // todo: migrate into slice
        let len = self.len();
        match len {
            0 => { return; },
            1..=0x4b => {
                (len as u8).enc(&mut writer);
            }
            0x4c..=0xffff => {
                OP_PUSHDATA1.into_u8().enc(&mut writer);
                (len as u8).enc(&mut writer);
            },
            0x10000..=0xffffffff => {
                OP_PUSHDATA2.into_u8().enc(&mut writer);
                (len as u16).enc(&mut writer);
            },
            _ => {
                OP_PUSHDATA4.into_u8().enc(&mut writer);
                (len as u32).enc(&mut writer);
            },
        }
        writer.write(self)
            .expect("can't write script push data");
        // self.enc(&mut writer);
        // writer
    }

    fn append_shapeshift_memo_for_address(address: String, mut writer: Self) -> Self {
        match base58::from_check(address.as_str()) {
            Ok(d) if d.len() == 21 => {
                let mut script_push = Vec::<u8>::new();
                if d[0] == BITCOIN_SCRIPT_ADDRESS {
                    // OP_SHAPESHIFT_SCRIPT
                    0xb3.enc(&mut script_push);
                } else {
                    // shapeshift is actually part of the message
                    // OP_SHAPESHIFT
                    0xb1.enc(&mut script_push);
                }
                script_push.extend(d.clone().drain(1..d.len()));
                OP_RETURN.into_u8().enc(&mut writer);
                // writer.append_script_push_data(script_push);
                script_push.append_script_push_data(&mut writer);
            },
            _ => panic!("can't convert from base58 check")
        }
        writer
    }

    // fn append_string(&mut self, data: String) {
    //     // NSUInteger l = [s lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    //     // [self appendVarInt:l];
    //     // [self appendBytes:s.UTF8String length:l];
    //     VarInt(data.len() as u64).enc(self);
    //     data.enc(self);
    // }

    fn script_elements(&self) -> Vec<ScriptElement> {
        let mut a = Vec::<ScriptElement>::new();
        let len = self.len();
        let chunk_size = &mut 0usize;
        let mut i = 0usize;
        'outer: while i < len {
            match self[i] {
                x @ 0 | x @ 0x4f..=0xff => {
                    *chunk_size = 1;
                    a.push(ScriptElement::Number(x));
                    i += *chunk_size;
                    continue 'outer;
                },
                0x4c => { // OP_PUSHDATA1
                    i += 1;
                    if i + std::mem::size_of::<u8>() > len {
                        break 'outer;
                    }
                    *chunk_size = self[i] as usize;
                    i += std::mem::size_of::<u8>();
                },
                0x4d => { // OP_PUSHDATA2
                    i += 1;
                    if i + std::mem::size_of::<u16>() > len {
                        break 'outer;
                    }
                    *chunk_size = (self[i] as u16).swap_bytes() as usize;
                    i += std::mem::size_of::<u16>();
                },
                0x4e => { // OP_PUSHDATA4
                    i += 1;
                    if i + std::mem::size_of::<u32>() > len {
                        break 'outer;
                    }
                    *chunk_size = (self[i] as u32).swap_bytes() as usize;
                    i += std::mem::size_of::<u32>();
                },
                _ => {
                    *chunk_size = self[i] as usize;
                    i += 1;
                }
            };
            if i + *chunk_size > len {
                return a;
            }
            let chunk = &self[i..i+*chunk_size];
            a.push(ScriptElement::Data(chunk, op_len(chunk)));
            i += *chunk_size;
        }
        a
    }
}

