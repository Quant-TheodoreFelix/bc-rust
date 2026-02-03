//! This crate contains an implementation of the Hash-Based Message Authentication Code (HMAC)
//! as specified in RFC2104, taking into account NIST Implementation Guidance in FIPS 140-2 IG A.8
//! and NIST SP 800-107-r1.
//!
//! # Examples
//! ## Constructing an object.
//!
//! HMAC objects can be constructed with any underlying hash function that implements [Hash].
//! Type aliases string, algorithm names, and a [MACFactory] are provided for the common HMAC-HASH algorithms.
//!
//! The following object instantiations are equivalent:
//!
//! ```
//! use hmac::HMAC_SHA256;
//! let hmac = HMAC_SHA256::new();
//! ```
//! and
//! ```
//! use hmac::HMAC;
//! use sha2::SHA256;
//! let hmac = HMAC::<SHA256>::new();
//! ```
//!
//! ## Computing a MAC
//! MAC functionality is accessed via the [MAC] trait.
//!
//! The simplest usage is via the one-shot functions.
//! ```
//! use core_interface::key_material::{KeyMaterial256, KeyType};
//! use core_interface::traits::MAC;
//!
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
//! let data: &[u8] = b"Hello, world!";
//! let output: Vec<u8> = hmac::HMAC_SHA256::new().mac(&key, data).unwrap();
//! ```
//!
//! More advanced usage will require creating an HMAC object to hold state between successive calls,
//! for example if input is received in chunks and not all available at the same time:
//!
//! ```
//! use core_interface::key_material::{KeyMaterial256, KeyType};
//! use core_interface::traits::MAC;
//! use hmac::HMAC_SHA256;
//!
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
//! let mut hmac = HMAC_SHA256::new();
//! hmac.init(&key);
//! hmac.do_update(b"Hello,");
//! hmac.do_update(b" world!");
//! let output: Vec<u8> = hmac.do_final().unwrap();
//! ```
//!
//! ## Verifying a MAC
//! MAC functionality is accessed via the [MAC] trait which provides functions for MAC verification.
//! The built-in verification functions use constant-time comparisons and so are *strongly recommended*
//! rather than re-computing the MAC value and comparing it yourself.
//!
//! The simplest usage is via the one-shot functions.
//! ```
//! use core_interface::key_material::{KeyMaterial256, KeyType};
//! use core_interface::traits::MAC;
//!
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
//! let data: &[u8] = b"Hello, world!";
//! hmac::HMAC_SHA256::new().verify(&key,
//!                                 data,
//!                                 b"\xa2\xd1\x2e\xcf\xfc\x41\xba\xf1\x23\xd6\x3e\x44\xfc\x27\x88\x90\x47\xcd\x08\xe7\x05\xd7\x0f\xa3\xb8\xaa\x8a\x5c\x18\x7c\x6c\xa9"
//!                                 ).unwrap();  // Returns Ok(()) on success,
//!                                              // or Err(MACError:VerificationFailed) on failure.
//! ```
//!
//! Similarly, a streaming version is available, which is identical to the streaming interface for
//! computing a mac value, but calls [do_verify_final] instead of [do_final].
//!
//! ```
//! use core_interface::key_material::{KeyMaterial256, KeyType};
//! use core_interface::traits::MAC;
//! use hmac::HMAC_SHA256;
//!
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
//! let mut hmac = HMAC_SHA256::new();
//! hmac.init(&key);
//! hmac.do_update(b"Hello,");
//! hmac.do_update(b" world!");
//! hmac.do_verify_final(b"\xa2\xd1\x2e\xcf\xfc\x41\xba\xf1\x23\xd6\x3e\x44\xfc\x27\x88\x90\x47\xcd\x08\xe7\x05\xd7\x0f\xa3\xb8\xaa\x8a\x5c\x18\x7c\x6c\xa9"
//!                     ).unwrap();  // Returns Ok(()) on success,
//!                                  // or Err(MACError:VerificationFailed) on failure.
//! ```


#![forbid(unsafe_code)]

#![allow(incomplete_features)] // because at time of writing, generic_const_exprs is not a stable feature
#![feature(generic_const_exprs)]

use core_interface::errors::{KeyMaterialError, MACError};
use core_interface::traits::{Algorithm, Hash, KeyMaterial, KeyedAlgorithm, SecurityStrength, MAC};
use core_interface::key_material::{KeyType};
use sha2::{SHA224, SHA256, SHA384, SHA512};
use sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};
use utils::ct;


/*** String constants ***/
pub const HMAC_SHA224_NAME: &str = "HMAC-SHA224";
pub const HMAC_SHA256_NAME: &str = "HMAC-SHA256";
pub const HMAC_SHA384_NAME: &str = "HMAC-SHA384";
pub const HMAC_SHA512_NAME: &str = "HMAC-SHA512";
pub const HMAC_SHA3_224_NAME: &str = "HMAC-SHA3-224";
pub const HMAC_SHA3_256_NAME: &str = "HMAC-SHA3-256";
pub const HMAC_SHA3_384_NAME: &str = "HMAC-SHA3-384";
pub const HMAC_SHA3_512_NAME: &str = "HMAC-SHA3-512";

/*** Type aliases ***/
#[allow(non_camel_case_types)]
pub type HMAC_SHA224 = HMAC<SHA224>;
impl Algorithm for HMAC_SHA224 {
    const ALG_NAME: &'static str = HMAC_SHA224_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_112bit;
}

#[allow(non_camel_case_types)]
pub type HMAC_SHA256 = HMAC<SHA256>;
impl Algorithm for HMAC_SHA256 {
    const ALG_NAME: &'static str = HMAC_SHA256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

#[allow(non_camel_case_types)]
pub type HMAC_SHA384 = HMAC<SHA384>;
impl Algorithm for HMAC_SHA384 {
    const ALG_NAME: &'static str = HMAC_SHA384_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

#[allow(non_camel_case_types)]
pub type HMAC_SHA512 = HMAC<SHA512>;
impl Algorithm for HMAC_SHA512 {
    const ALG_NAME: &'static str = HMAC_SHA512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

#[allow(non_camel_case_types)]
pub type HMAC_SHA3_224 = HMAC<SHA3_224>;
impl Algorithm for HMAC_SHA3_224 {
    const ALG_NAME: &'static str = HMAC_SHA3_224_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_112bit;
}

#[allow(non_camel_case_types)]
pub type HMAC_SHA3_256 = HMAC<SHA3_256>;
impl Algorithm for HMAC_SHA3_256 {
    const ALG_NAME: &'static str = HMAC_SHA3_256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

#[allow(non_camel_case_types)]
pub type HMAC_SHA3_384 = HMAC<SHA3_384>;
impl Algorithm for HMAC_SHA3_384 {
    const ALG_NAME: &'static str = HMAC_SHA3_384_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

#[allow(non_camel_case_types)]
pub type HMAC_SHA3_512 = HMAC<SHA3_512>;
impl Algorithm for HMAC_SHA3_512 {
    const ALG_NAME: &'static str = HMAC_SHA3_512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

// TODO: is there a rustacious way to extract this from HASH?
const LARGEST_HASHER_OUTPUT_LEN: usize = 64;

// HMAC implements RFC 2104.
#[derive(Clone)]
pub struct HMAC<HASH: Hash + Default> {
    hasher: HASH,
    key: [u8; LARGEST_HASHER_OUTPUT_LEN],
    key_len: usize, // Doing it this way to avoid needing a vec, so that this can be made no_std friendly.
    initialized: bool,
    allow_weak_keys: bool,
}

// See definitions in RFC 2104 Section 2.
const IPAD_BYTE: u8 = 0x36;
const OPAD_BYTE: u8 = 0x5C;

// Per FIPS 140-2 IG A.8 Use of a truncated HMAC (matching NIST SP 800-107-r1
// Section 5.3.3. Truncation of HMAC), says that the minimum truncation of a
// HMAC for tagging should be 32 bits; this exceeds the lower bound set by
// IETF RFC 2104 Section 5 Truncated output, which sets the lower bound to be
// half of the hash's length and no fewer than 80 bits.
//
// However, as we feel there should be a minimum limit (and have an author
// work around this via explicit truncation manually afterwards), but not
// be too strict about it,
pub const MIN_FIPS_DIGEST_LEN: usize = 4; // 32 / 8;

impl<HASH: Hash + Default> HMAC<HASH> {
    // pub fn from_key(key: &[u8]) -> Self {
    //     Self { hasher: HASH::default(), key: Vec::from(key), initialized: false }
    // }

    pub fn new() -> Self {
        Self {
            hasher: HASH::default(),
            key: [0u8; LARGEST_HASHER_OUTPUT_LEN],
            key_len: 0,
            initialized: false,
            allow_weak_keys: false,
        }
    }

    fn pad_key_into_hasher(&mut self, padding: u8) {
        // TODO: it would be nice to be able to statically extract the length of HASH and not need a Vec or over-sized array here.
        // TODO: make this no_std-friendly
        let mut padded = vec![0u8; self.hasher.block_bitlen() / 8];

        // Per RFC 2104 Section 2, if the application key exceeds the block
        // length of the underlying hashes algorithm, we apply a hash invocation
        // over the key first.
        // if self.key_len > self.hasher.block_bitlen() / 8 {
        //     HASH::default().hash_out(&self.key[..self.key_len], &mut padded[..self.hasher.output_len()])?;
        // } else {
        // TODO: does this need a guard for a key_len longer than the block length?
            padded[..self.key_len].copy_from_slice(&self.key[..self.key_len]);
        // }

        // XXX: easier way to xor over Vec?
        for entry in &mut padded {
            *entry ^= padding;
        }

        // Per RFC 2104 Section 2, write the padded key into the stream prior
        // to any other data.
        self.hasher.do_update(&padded)
    }

    /// the out buffer can be oversized, but not less than the MIN_FIPS_DIGEST_LENGTH
    /// Returns the number of bytes written.
    fn do_final_internal_out(mut self, out: &mut [u8]) -> Result<usize, MACError> {
        if out.len() < MIN_FIPS_DIGEST_LEN {
            return Err(MACError::InvalidLength("HMAC truncation too short for FIPS 140-2 guidelines"));
        }

        // Per RFC 2104 Section 2, save our inner digest to calculate our
        // outer digest. Note that we can't (necessarily) reuse out as a
        // scratch pad here: if we're truncating the output but not
        // truncating the underlying hashes, we'd lose bytes and compute an
        // invalid outer hashes.
        // TODO: rework this to be no_std friendly (ie no vec!)
        let mut ihash = vec![0u8; self.hasher.output_len()];
        self.hasher.do_final_out(&mut ihash);

        // ohash
        self.hasher = HASH::default();
        self.pad_key_into_hasher(OPAD_BYTE);
        self.hasher.do_update(&ihash);
        Ok(self.hasher.do_final_out(out))
    }
}

impl<HASH: Hash + Default> Default for HMAC<HASH> {
    fn default() -> Self {
        Self::new()
    }
}

impl<HASH: Hash + Default> KeyedAlgorithm for HMAC<HASH> {
    fn allow_weak_keys(&mut self) {
        self.allow_weak_keys = true;
    }
}

// TODO: potential feature: add an interface that pre-computes the intermediate values (K XOR ipad) and (K XOR opad)
// TODO for a given key as described in RFC2104 section 4.
// TODO: This is essentially a "batch mode" where you want to perform many MACs or Verifications with the same key
// TODO: against different data.

impl<HASH: Hash + Default> MAC for HMAC<HASH> {
    fn output_len(&self) -> usize {
        self.hasher.output_len()
    }

    fn mac(&self, key: &impl KeyMaterial, data: &[u8]) -> Result<Vec<u8>, MACError> {
        // TODO: make this match the hasher's output len
        let mut out = vec![0_u8; self.hasher.output_len()];
        let bytes_written = self.mac_out(key, data, &mut out)?;
        Ok(out[..bytes_written].to_vec())
    }

    fn mac_out(&self, key: &impl KeyMaterial, data: &[u8], mut out: &mut [u8]) -> Result<usize, MACError> {
        let mut hmac = Self::default();

        // if init throws an error about the key's security strength, we want to catch it and return it
        // at the end.
        match hmac.init(key) {
            Ok(()) => { /* good */ },
            Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(s))) => {
                if !self.allow_weak_keys {
                    return Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(s)));
                } /* else, carry on */
            },
            Err(e) => { return Err(e) },
        };
        hmac.do_update(data)?;
        hmac.do_final_out(&mut out)
    }

    fn verify(&self, key: &impl KeyMaterial, data: &[u8], mac: &[u8]) -> Result<(), MACError> {
        let mut hmac = Self::default();

        // Swallow an error about the key's security strength, since we're verifying anyway;
        // it would be worse for overall security for someone to erroneously think the verification passed
        // than to miss a warning about a potentially weak key that the verfier doesn't really control anyway.
        match hmac.init(key) {
            Ok(()) | Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => { /* fine */},
            Err(e) => return Err(e),
        }
        hmac.do_update(data)?;
        hmac.do_verify_final(mac)
    }

    /// Salt is optional, which is indicated by providing an uninitialized KeyMaterial object of length zero,
    /// the capacity is irrelevant, so KeyMateriol256::new() or KeyMaterial_internal::<0>::new() would both count as an absent salt.
    fn init(&mut self, key: &impl KeyMaterial) -> Result<(), MACError> {
        // check that the key is of type KeyMaterial::MACKey
        // Make an exception for the zero-length key or keys of zero entropy, which is allowed, and it's just a nuisance to
        // force users to set KeyType::MACKey for a zero-length key.
        if key.key_len() != 0 && key.key_type() != KeyType::Zeroized && key.key_type() != KeyType::MACKey {
            return Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(
                "Key type must be a MAC key.",
            )));
        }

        // import the key material as bytes.
        // Per RFC 2104 Section 2, if the application key exceeds the block
        // length of the underlying hashes algorithm, we apply a hash invocation
        // over the key first.

        if key.key_len() > self.hasher.block_bitlen() / 8 {
            // then we have to pre-hash it -- use a new instance of the hasher rather than the internal one
            HASH::default().hash_out(key.ref_to_bytes(), &mut self.key[..self.hasher.output_len()]);
            self.key_len = self.hasher.output_len();

        } else {
            self.key[..key.key_len()].copy_from_slice(key.ref_to_bytes());
            self.key_len = key.key_len();
        }
        
        self.pad_key_into_hasher(IPAD_BYTE);
        self.initialized = true;

        // check that the key had enough security level
        if !self.allow_weak_keys && key.security_strength() < HASH::default().max_security_strength() {
            Err(KeyMaterialError::SecurityStrength("HMAC::init(): provided key has a lower security strength than the instantiated HMAC"))?
        } else {
            Ok(())
        }
    }

    fn do_update(&mut self, data: &[u8]) -> Result<(), MACError> {
        if !self.initialized { return Err(MACError::InvalidState("do_update() before init()")) }  // TODO: is this actually necessary, or can it be designed so that this is structurally impossible?

        Ok(self.hasher.do_update(data))
    }

    fn do_final(self) -> Result<Vec<u8>, MACError> {
        if !self.initialized { return Err(MACError::InvalidState("do_update() before init()")) }  // TODO: is this actually necessary, or can it be designed so that this is structurally impossible?

        let mut out = vec![0_u8; self.hasher.output_len()];
        self.do_final_internal_out(&mut out)?;
        Ok(out)
    }

    fn do_final_out(self, mut out: &mut [u8]) -> Result<usize, MACError> {
        self.do_final_internal_out(&mut out)
    }

    fn do_verify_final(self, mac: &[u8]) -> Result<(), MACError> {
        if !self.initialized { return Err(MACError::InvalidState("do_update() before init()")) }  // TODO: is this actually necessary, or can it be designed so that this is structurally impossible?

        let mut out = vec![0_u8; HASH::default().output_len()];
        let output_len = self.do_final_internal_out(&mut out)?;

        if mac.len() != output_len { return Err(MACError::InvalidLength("Provided MAC value is not the correct length")); }

        if ct::ct_eq_bytes(mac, &out[..output_len]) {
            Ok(())
        } else {
            Err(MACError::VerificationFailed)
        }
    }

    fn max_security_strength(&self) -> SecurityStrength {
        HASH::default().max_security_strength()
    }
}
