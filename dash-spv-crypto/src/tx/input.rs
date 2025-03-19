use dashcore::blockdata::script::owned::ScriptBuf;
use dashcore::blockdata::transaction::outpoint::OutPoint;
use dashcore::blockdata::transaction::txin::TxIn;
use dashcore::hashes::Hash;
use dashcore::hash_types::Txid;
use dashcore::secp256k1::hashes::hex::DisplayHex;

#[derive(Clone)]
#[ferment_macro::export]
pub struct TransactionInput {
    pub input_hash: [u8; 32],
    pub index: u32,
    pub script: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
    pub sequence: u32,
}

impl From<TransactionInput> for TxIn {
    fn from(value: TransactionInput) -> Self {
        TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array(value.input_hash), vout: value.index },
            script_sig: ScriptBuf(value.signature.unwrap_or(value.script.unwrap_or_default())),
            sequence: value.sequence,
            witness: Default::default(),
        }
    }
}
// impl From<TxIn> for TransactionInput {
//     fn from(value: TxIn) -> Self {
//         TransactionInput {
//             input_hash: value.previous_output.txid.to_byte_array(),
//             index: value.previous_output.vout,
//             script: value.script_sig.as_script(),
//             signature: None,
//             sequence: value.sequence,
//         }
//     }
// }

impl std::fmt::Debug for TransactionInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionInput")
            .field("input_hash", &self.input_hash)
            .field("index", &self.index)
            .field(
                "script",
                &self.script.as_ref().unwrap_or(&Vec::<u8>::new()).to_lower_hex_string(),
            )
            .field(
                "signature",
                &self
                    .signature
                    .as_ref()
                    .unwrap_or(&Vec::<u8>::new())
                    .to_lower_hex_string(),
            )
            .field("sequence", &self.sequence)
            .finish()
    }
}

// impl Encodable for TransactionInput {
//     #[inline]
//     fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
//         let mut offset = 0;
//         offset += self.input_hash.consensus_encode(writer)?;
//         offset += self.index.consensus_encode(writer)?;
//         offset += match self.signature {
//             Some(ref signature) => signature.consensus_encode(writer)?,
//             None => 0
//         };
//         offset += self.sequence.consensus_encode(writer)?;
//         Ok(offset)
//     }
// }
//
// impl Decodable for TransactionInput {
//     #[inline]
//     fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, dashcore::consensus::encode::Error> {
//         let input_hash = <[u8; 32]>::consensus_decode(reader)?;
//         let index = u32::consensus_decode(reader)?;
//         let signature: Option<Vec<u8>> = Vec::consensus_decode(reader).ok();
//         let sequence = u32::consensus_decode(reader)?;
//         Ok(Self { input_hash, index, signature, sequence, script: None })
//     }
// }
//
//
// impl<'a> TryRead<'a, Endian> for TransactionInput {
//     fn try_read(bytes: &'a [u8], _endian: Endian) -> byte::Result<(Self, usize)> {
//         let offset = &mut 0;
//         let input_hash = bytes.read_with::<UInt256>(offset, LE)?.0;
//         let index = bytes.read_with::<u32>(offset, LE)?;
//         let signature = match bytes.read_with::<VarBytes>(offset, LE) {
//             Ok(data) => Some(data.1.to_vec()),
//             Err(_err) => None,
//         };
//         let sequence = bytes.read_with::<u32>(offset, LE)?;
//         let input = TransactionInput {
//             input_hash,
//             index,
//             script: None,
//             signature,
//             sequence,
//         };
//         Ok((input, *offset))
//     }
// }
