/**
 * A txout script template with a specific destination. It is either:
 *  * CNoDestination: no destination set
 *  * CKeyID: TxoutType::PUBKEYHASH destination
 *  * CScriptID: TxoutType::SCRIPTHASH destination
 *  A CTxDestination is the internal data type encoded in a bitcoin address
 */
pub type TxDestination = Option<Vec<u8>>;
