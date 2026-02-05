//! MAC factory for creating instances of algorithms that implement the [MAC] trait.
//!
//! As with all Factory objects, this implements constructions from strings and defaults, and
//! returns a [MACFactory] object which itself implements the [MAC] trait as a pass-through to the underlying algorithm.
//!
//! Example usage:
//! Generating and verifying a MAC value for a given piece of data:
//!
//! ```
//! use core_interface::key_material::{KeyMaterial256, KeyType};
//! use core_interface::traits::MAC;
//! use encoders::hex;
//! use factory::AlgorithmFactory;
//! use factory::mac_factory::MACFactory;
//!
//! let data = b"Hi There!";
//! let key = KeyMaterial256::from_bytes_as_type(
//!         // Note: This would be a bad key to use in a production application!
//!         // But we'll hard-code a silly key for demonstration purposes.
//!         &hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
//!         KeyType::MACKey,
//!     ).unwrap();
//! let hmac = MACFactory::new(hmac::HMAC_SHA3_256_NAME).unwrap();
//!
//! // Generate the MAC value
//! let mac_value: Vec<u8> = hmac.mac(&key, data).unwrap();
//!
//! // Verify the MAC value
//! match hmac.verify(&key, data, &mac_value,) {
//!     Ok(()) => println!("MAC verified successfully!"),
//!     Err(e) => println!("MAC verification failed"),
//! }
//! ```
//!
//! You can equivalently construct an instance of [MACFactory] by string instead of using the constant:
//!
//! ```
//! use factory::AlgorithmFactory;
//! use factory::mac_factory::MACFactory;
//!
//! let hmac = MACFactory::new("HMAC-SHA256").unwrap();
//! ```
//!
//! Or if you don't particularly care which algorithm is used, you can use the built-in default:
//!
//! ```
//! use factory::AlgorithmFactory;
//! use factory::mac_factory::MACFactory;
//!
//! let hmac = MACFactory::default();
//! ```

use bouncycastle_core_interface::errors::MACError;
use crate::{FactoryError, DEFAULT, DEFAULT_128_BIT, DEFAULT_256_BIT};
use bouncycastle_core_interface::traits::{KeyMaterial, SecurityStrength, MAC};
use bouncycastle_hmac as hmac;
use bouncycastle_sha2 as sha2;
use bouncycastle_sha3 as sha3;
use bouncycastle_hmac::{HMAC_SHA224_NAME, HMAC_SHA256_NAME, HMAC_SHA384_NAME, HMAC_SHA512_NAME};
use bouncycastle_hmac::{HMAC_SHA3_224_NAME, HMAC_SHA3_256_NAME, HMAC_SHA3_384_NAME, HMAC_SHA3_512_NAME};

/*** Defaults ***/
pub const DEFAULT_MAC_NAME: &str = HMAC_SHA256_NAME;
pub const DEFAULT_128BIT_MAC_NAME: &str = HMAC_SHA256_NAME;
pub const DEFAULT_256BIT_MAC_NAME: &str = HMAC_SHA256_NAME;

#[allow(non_camel_case_types)]

/// MACFactory deviates from the usual AlgorithmFactory trait because MAC objects do not have a no-arg constructor;
/// instead they have a constructor that takes a [KeyMaterial] and can return an error.
pub enum MACFactory {
    // All members must impl MAC.
    HMAC_SHA224(hmac::HMAC<sha2::SHA224>),
    HMAC_SHA256(hmac::HMAC<sha2::SHA256>),
    HMAC_SHA384(hmac::HMAC<sha2::SHA384>),
    HMAC_SHA512(hmac::HMAC<sha2::SHA512>),
    HMAC_SHA3_224(hmac::HMAC<sha3::SHA3_224>),
    HMAC_SHA3_256(hmac::HMAC<sha3::SHA3_256>),
    HMAC_SHA3_384(hmac::HMAC<sha3::SHA3_384>),
    HMAC_SHA3_512(hmac::HMAC<sha3::SHA3_512>),
}


impl MACFactory {
    pub fn default(key: &impl KeyMaterial) -> Result<Self, FactoryError> {
        Self::new(DEFAULT_MAC_NAME, key)
    }

    pub fn default_128_bit(key: &impl KeyMaterial) -> Result<Self, FactoryError> {
        Self::new(DEFAULT_128BIT_MAC_NAME, key)
    }

    pub fn default_256_bit(key: &impl KeyMaterial) -> Result<Self, FactoryError> {
        Self::new(DEFAULT_256BIT_MAC_NAME, key)
    }

    pub fn new(alg_name: &str, key: &impl KeyMaterial) -> Result<Self, FactoryError> {
        match alg_name {
            DEFAULT => Self::default(key),
            DEFAULT_128_BIT => Self::default_128_bit(key),
            DEFAULT_256_BIT => Self::default_256_bit(key),
            HMAC_SHA224_NAME => Ok(Self::HMAC_SHA224(hmac::HMAC::<sha2::SHA224>::new(key)?)),
            HMAC_SHA256_NAME => Ok(Self::HMAC_SHA256(hmac::HMAC::<sha2::SHA256>::new(key)?)),
            HMAC_SHA384_NAME => Ok(Self::HMAC_SHA384(hmac::HMAC::<sha2::SHA384>::new(key)?)),
            HMAC_SHA512_NAME => Ok(Self::HMAC_SHA512(hmac::HMAC::<sha2::SHA512>::new(key)?)),
            HMAC_SHA3_224_NAME => Ok(Self::HMAC_SHA3_224(hmac::HMAC::<sha3::SHA3_224>::new(key)?)),
            HMAC_SHA3_256_NAME => Ok(Self::HMAC_SHA3_256(hmac::HMAC::<sha3::SHA3_256>::new(key)?)),
            HMAC_SHA3_384_NAME => Ok(Self::HMAC_SHA3_384(hmac::HMAC::<sha3::SHA3_384>::new(key)?)),
            HMAC_SHA3_512_NAME => Ok(Self::HMAC_SHA3_512(hmac::HMAC::<sha3::SHA3_512>::new(key)?)),
            _ => Err(FactoryError::UnsupportedAlgorithm(format!("The algorithm: \"{}\" is not a known MAC", alg_name))),
        }
    }
}

impl MAC for MACFactory {
    /// This is a dummy function, required by the [MAC] trait. Don't call it, it doesn't do anything.
    fn new(_key: &impl KeyMaterial) -> Result<Self, MACError> {
        unimplemented!()
    }

    /// This is a dummy function, required by the [MAC] trait. Don't call it, it doesn't do anything.
    fn new_allow_weak_key(_key: &impl KeyMaterial) -> Result<Self, MACError> {
        unimplemented!()
    }

    fn output_len(&self) -> usize {
        match self {
            Self::HMAC_SHA224(h) => h.output_len(),
            Self::HMAC_SHA256(h) => h.output_len(),
            Self::HMAC_SHA384(h) => h.output_len(),
            Self::HMAC_SHA512(h) => h.output_len(),
            Self::HMAC_SHA3_224(h) => h.output_len(),
            Self::HMAC_SHA3_256(h) => h.output_len(),
            Self::HMAC_SHA3_384(h) => h.output_len(),
            Self::HMAC_SHA3_512(h) => h.output_len(),
        }
    }

    fn mac(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::HMAC_SHA224(h) => h.mac(data),
            Self::HMAC_SHA256(h) => h.mac(data),
            Self::HMAC_SHA384(h) => h.mac(data),
            Self::HMAC_SHA512(h) => h.mac(data),
            Self::HMAC_SHA3_224(h) => h.mac(data),
            Self::HMAC_SHA3_256(h) => h.mac(data),
            Self::HMAC_SHA3_384(h) => h.mac(data),
            Self::HMAC_SHA3_512(h) => h.mac(data),
        }
    }

    fn mac_out(self, data: &[u8], out: &mut [u8]) -> Result<usize, MACError> {
        match self {
            Self::HMAC_SHA224(h) => h.mac_out(data, out),
            Self::HMAC_SHA256(h) => h.mac_out(data, out),
            Self::HMAC_SHA384(h) => h.mac_out(data, out),
            Self::HMAC_SHA512(h) => h.mac_out(data, out),
            Self::HMAC_SHA3_224(h) => h.mac_out(data, out),
            Self::HMAC_SHA3_256(h) => h.mac_out(data, out),
            Self::HMAC_SHA3_384(h) => h.mac_out(data, out),
            Self::HMAC_SHA3_512(h) => h.mac_out(data, out),
        }
    }

    fn verify(self, data: &[u8], mac: &[u8]) -> bool {
        match self {
            Self::HMAC_SHA224(h) => h.verify(data, mac),
            Self::HMAC_SHA256(h) => h.verify(data, mac),
            Self::HMAC_SHA384(h) => h.verify(data, mac),
            Self::HMAC_SHA512(h) => h.verify(data, mac),
            Self::HMAC_SHA3_224(h) => h.verify(data, mac),
            Self::HMAC_SHA3_256(h) => h.verify(data, mac),
            Self::HMAC_SHA3_384(h) => h.verify(data, mac),
            Self::HMAC_SHA3_512(h) => h.verify(data, mac),
        }
    }

    fn do_update(&mut self, data: &[u8]) {
        match self {
            Self::HMAC_SHA224(h) => h.do_update(data),
            Self::HMAC_SHA256(h) => h.do_update(data),
            Self::HMAC_SHA384(h) => h.do_update(data),
            Self::HMAC_SHA512(h) => h.do_update(data),
            Self::HMAC_SHA3_224(h) => h.do_update(data),
            Self::HMAC_SHA3_256(h) => h.do_update(data),
            Self::HMAC_SHA3_384(h) => h.do_update(data),
            Self::HMAC_SHA3_512(h) => h.do_update(data),
        }
    }

    fn do_final(self) -> Vec<u8> {
        match self {
            Self::HMAC_SHA224(h) => h.do_final(),
            Self::HMAC_SHA256(h) => h.do_final(),
            Self::HMAC_SHA384(h) => h.do_final(),
            Self::HMAC_SHA512(h) => h.do_final(),
            Self::HMAC_SHA3_224(h) => h.do_final(),
            Self::HMAC_SHA3_256(h) => h.do_final(),
            Self::HMAC_SHA3_384(h) => h.do_final(),
            Self::HMAC_SHA3_512(h) => h.do_final(),
        }
    }

    fn do_final_out(self, mut out: &mut [u8]) -> Result<usize, MACError> {
        match self {
            Self::HMAC_SHA224(h) => h.do_final_out(&mut out),
            Self::HMAC_SHA256(h) => h.do_final_out(&mut out),
            Self::HMAC_SHA384(h) => h.do_final_out(&mut out),
            Self::HMAC_SHA512(h) => h.do_final_out(&mut out),
            Self::HMAC_SHA3_224(h) => h.do_final_out(&mut out),
            Self::HMAC_SHA3_256(h) => h.do_final_out(&mut out),
            Self::HMAC_SHA3_384(h) => h.do_final_out(&mut out),
            Self::HMAC_SHA3_512(h) => h.do_final_out(&mut out),
        }
    }

    fn do_verify_final(self, mac: &[u8]) -> bool {
        match self {
            Self::HMAC_SHA224(h) => h.do_verify_final(mac),
            Self::HMAC_SHA256(h) => h.do_verify_final(mac),
            Self::HMAC_SHA384(h) => h.do_verify_final(mac),
            Self::HMAC_SHA512(h) => h.do_verify_final(mac),
            Self::HMAC_SHA3_224(h) => h.do_verify_final(mac),
            Self::HMAC_SHA3_256(h) => h.do_verify_final(mac),
            Self::HMAC_SHA3_384(h) => h.do_verify_final(mac),
            Self::HMAC_SHA3_512(h) => h.do_verify_final(mac),
        }
    }

    fn max_security_strength(&self) -> SecurityStrength {
        match self {
            Self::HMAC_SHA224(h) => h.max_security_strength(),
            Self::HMAC_SHA256(h) => h.max_security_strength(),
            Self::HMAC_SHA384(h) => h.max_security_strength(),
            Self::HMAC_SHA512(h) => h.max_security_strength(),
            Self::HMAC_SHA3_224(h) => h.max_security_strength(),
            Self::HMAC_SHA3_256(h) => h.max_security_strength(),
            Self::HMAC_SHA3_384(h) => h.max_security_strength(),
            Self::HMAC_SHA3_512(h) => h.max_security_strength(),
        }
    }
}