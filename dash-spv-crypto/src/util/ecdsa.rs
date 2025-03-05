// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! ECDSA Bitcoin Keys
//!
//! ECDSA keys used in Bitcoin that can be roundtrip (de)serialized.
//!

use core::{ops, str::FromStr};
use core::fmt::{self, Write as _fmtWrite};
use std::io;
use secp256k1::{self, Secp256k1};

use dashcore::hash_types::{PubkeyHash, WPubkeyHash};
use dashcore::hashes::{Hash, hash160};
use dashcore::network::constants::Network;
use crate::util::base58;
use crate::util::key::Error;

/// A Bitcoin ECDSA public key
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey {
    /// Whether this public key should be serialized as compressed
    pub compressed: bool,
    /// The actual ECDSA key
    pub key: secp256k1::PublicKey,
}

impl PublicKey {
    /// Constructs compressed ECDSA public key from the provided generic Secp256k1 public key
    pub fn new(key: secp256k1::PublicKey) -> PublicKey {
        PublicKey { compressed: true, key, }
    }

    /// Constructs uncompressed (legacy) ECDSA public key from the provided generic Secp256k1
    /// public key
    pub fn new_uncompressed(key: secp256k1::PublicKey) -> PublicKey {
        PublicKey { compressed: false, key, }
    }

    /// Returns bitcoin 160-bit hash of the public key
    pub fn pubkey_hash(&self) -> PubkeyHash {
        if self.compressed {
            PubkeyHash::hash(&self.key.serialize())
        } else {
            PubkeyHash::hash(&self.key.serialize_uncompressed())
        }
    }

    /// Returns bitcoin 160-bit hash of the public key for witness program
    pub fn wpubkey_hash(&self) -> Option<WPubkeyHash> {
        if self.compressed {
            Some(WPubkeyHash::from_raw_hash(hash160::Hash::hash(&self.key.serialize())))
        } else {
            // We can't create witness pubkey hashes for an uncompressed
            // public keys
            None
        }
    }

    /// Write the public key into a writer
    pub fn write_into<W: io::Write>(&self, mut writer: W) -> Result<(), io::Error> {
        if self.compressed {
            writer.write_all(&self.key.serialize())
        } else {
            writer.write_all(&self.key.serialize_uncompressed())
        }
    }

    /// Read the public key from a reader
    ///
    /// This internally reads the first byte before reading the rest, so
    /// use of a `BufReader` is recommended.
    pub fn read_from<R: io::Read>(mut reader: R) -> Result<Self, io::Error> {
        let mut bytes = [0; 65];

        reader.read_exact(&mut bytes[0..1])?;
        let bytes = if bytes[0] < 4 {
            &mut bytes[..33]
        } else {
            &mut bytes[..65]
        };

        reader.read_exact(&mut bytes[1..])?;
        Self::from_slice(bytes).map_err(|e|{
            // Need a static string for core2
            #[cfg(feature = "std")]
            let reason = e;
            #[cfg(not(feature = "std"))]
            let reason = match e {
                Error::Base58(_) => "base58 error",
                Error::Secp256k1(_) => "secp256k1 error",
            };
            io::Error::new(io::ErrorKind::InvalidData, reason)
        })
    }

    /// Serialize the public key to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_into(&mut buf).expect("vecs don't error");
        buf
    }

    /// Deserialize a public key from a slice
    pub fn from_slice(data: &[u8]) -> Result<PublicKey, Error> {
        let compressed: bool = match data.len() {
            33 => true,
            65 => false,
            len => { return Err(base58::Error::InvalidLength(len).into()); },
        };

        Ok(PublicKey { compressed, key: secp256k1::PublicKey::from_slice(data)? })
    }

    /// Computes the public key as supposed to be used with this secret
    pub fn from_private_key<C: secp256k1::Signing>(secp: &Secp256k1<C>, sk: &PrivateKey) -> PublicKey {
        sk.public_key(secp)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.compressed {
            for ch in &self.key.serialize()[..] {
                write!(f, "{:02x}", ch)?;
            }
        } else {
            for ch in &self.key.serialize_uncompressed()[..] {
                write!(f, "{:02x}", ch)?;
            }
        }
        Ok(())
    }
}

impl FromStr for PublicKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<PublicKey, Error> {
        let key = secp256k1::PublicKey::from_str(s)?;
        Ok(PublicKey { key, compressed: s.len() == 66 })
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
/// A Bitcoin ECDSA private key
pub struct PrivateKey {
    /// Whether this private key should be serialized as compressed
    pub compressed: bool,
    /// The network on which this key should be used
    pub network: Network,
    /// The actual ECDSA key
    pub key: secp256k1::SecretKey,
}

impl PrivateKey {
    /// Constructs compressed ECDSA private key from the provided generic Secp256k1 private key
    /// and the specified network
    pub fn new(key: secp256k1::SecretKey, network: Network) -> PrivateKey {
        PrivateKey { compressed: true, network, key, }
    }

    /// Constructs uncompressed (legacy) ECDSA private key from the provided generic Secp256k1
    /// private key and the specified network
    pub fn new_uncompressed(key: secp256k1::SecretKey, network: Network) -> PrivateKey {
        PrivateKey { compressed: false, network, key, }
    }

    /// Creates a public key from this private key
    pub fn public_key<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> PublicKey {
        PublicKey {
            compressed: self.compressed,
            key: secp256k1::PublicKey::from_secret_key(secp, &self.key)
        }
    }

    /// Serialize the private key to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key[..].to_vec()
    }

    /// Deserialize a private key from a slice
    pub fn from_slice(data: &[u8], network: Network) -> Result<PrivateKey, Error> {
        Ok(PrivateKey::new(secp256k1::SecretKey::from_slice(data)?, network))
    }

    /// Format the private key to WIF format.
    pub fn fmt_wif(&self, fmt: &mut dyn fmt::Write) -> fmt::Result {
        let mut ret = [0; 34];
        ret[0] = match self.network {
            Network::Dash => 128,
            _ => 239,
        };
        ret[1..33].copy_from_slice(&self.key[..]);
        let privkey = if self.compressed {
            ret[33] = 1;
            base58::check_encode_slice(&ret[..])
        } else {
            base58::check_encode_slice(&ret[..33])
        };
        fmt.write_str(&privkey)
    }

    /// Get WIF encoding of this private key.
    pub fn to_wif(&self) -> String {
        let mut buf = String::new();
        buf.write_fmt(format_args!("{}", self)).unwrap();
        buf.shrink_to_fit();
        buf
    }

    /// Parse WIF encoded private key.
    pub fn from_wif(wif: &str) -> Result<PrivateKey, Error> {
        let data = base58::from_check(wif)?;
        let compressed = match data.len() {
            33 => false,
            34 => true,
            _ => { return Err(Error::Base58(base58::Error::InvalidLength(data.len()))); }
        };
        let network = match data[0] {
            128 => Network::Dash,
            239 => Network::Testnet,
            x=> { return Err(Error::Base58(base58::Error::InvalidAddressVersion(x))); }
        };
        Ok(PrivateKey { compressed, network, key: secp256k1::SecretKey::from_slice(&data[1..33])? })
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_wif(f)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[private key data]")
    }
}

impl FromStr for PrivateKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<PrivateKey, Error> {
        PrivateKey::from_wif(s)
    }
}

impl ops::Index<ops::RangeFull> for PrivateKey {
    type Output = [u8];
    fn index(&self, _: ops::RangeFull) -> &[u8] {
        &self.key[..]
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl ::serde::Serialize for PrivateKey {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> ::serde::Deserialize<'de> for PrivateKey {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<PrivateKey, D::Error> {
        struct WifVisitor;

        impl<'de> ::serde::de::Visitor<'de> for WifVisitor {
            type Value = PrivateKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("an ASCII WIF string")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where E: ::serde::de::Error {
                if let Ok(s) = ::core::str::from_utf8(v) {
                    PrivateKey::from_str(s).map_err(E::custom)
                } else {
                    Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where E: ::serde::de::Error {
                PrivateKey::from_str(v).map_err(E::custom)
            }
        }
        d.deserialize_str(WifVisitor)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl ::serde::Serialize for PublicKey {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            if self.compressed {
                s.serialize_bytes(&self.key.serialize()[..])
            } else {
                s.serialize_bytes(&self.key.serialize_uncompressed()[..])
            }
        }
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> ::serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        if d.is_human_readable() {
            struct HexVisitor;

            impl<'de> ::serde::de::Visitor<'de> for HexVisitor {
                type Value = PublicKey;

                fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                    formatter.write_str("an ASCII hex string")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where E: ::serde::de::Error {
                    if let Ok(hex) = ::core::str::from_utf8(v) {
                        PublicKey::from_str(hex).map_err(E::custom)
                    } else {
                        Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                    }
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where E: ::serde::de::Error {
                    PublicKey::from_str(v).map_err(E::custom)
                }
            }
            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl<'de> ::serde::de::Visitor<'de> for BytesVisitor {
                type Value = PublicKey;

                fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                    formatter.write_str("a bytestring")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where E: ::serde::de::Error {
                    PublicKey::from_slice(v).map_err(E::custom)
                }
            }
            d.deserialize_bytes(BytesVisitor)
        }
    }
}

