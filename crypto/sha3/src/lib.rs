//! Implements SHA3 as per NIST FIPS 202.
//!
//! # Examples
//! ## Hash
//! Hash functionality is accessed via the [Hash] trait,
//! which is implemented by [SHA3_224], [SHA3_256], [SHA3_384] and [SHA3_512].
//!
//! The simplest usage is via the one-shot functions.
//! ```
//! use core_interface::traits::Hash;
//!
//! let data: &[u8] = b"Hello, world!";
//! let output: Vec<u8> = sha3::SHA3_256::new().hash(data);
//! ```
//!
//! More advanced usage will require creating a SHA3 or SHAKE object to hold state between successive calls,
//! for example if input is received in chunks and not all available at the same time:
//!
//! ```
//! use core_interface::traits::Hash;
//!
//! let data: &[u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F
//!                     \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F
//!                     \x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F
//!                     \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
//! let mut sha3 = sha3::SHA3_256::new();
//!
//! for chunk in data.chunks(16) {
//!     sha3.do_update(chunk);
//! }
//!
//! let output: Vec<u8> = sha3.do_final();
//! ```
//!
//! It is also possible to provide input where the final byte contains less than 8 bits of data (ie is a partial byte);
//! for example, the following code uses only 3 bits of the final byte:
//! ```
//! use core_interface::traits::Hash;
//!
//! let data: &[u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
//! let mut sha3 = sha3::SHA3_256::new();
//! sha3.do_update(&data[..data.len()-1]);
//! let final_byte = data[data.len()-1];
//! let output: Vec<u8> = sha3.do_final_partial_bits(final_byte, 3).expect("Failed to finalize hash state.");
//! ```
//!
//! ## XOF
//! SHA3 offers Extendable-Output Functions in the form of SHAKE, which is accessed through the [XOF] trait,
//! which is implemented by [SHAKE128] and [SHAKE256].
//! The difference from [Hash] is that SHAKE can produce output of any length.
//!
//! The simplest usage is via the static functions. The following example produces a 16 byte (128-bit) and 16KiB output:
//!```
//! use core_interface::traits::XOF;
//!
//! let data: &[u8] = b"Hello, world!";
//! let output_16byte: Vec<u8> = sha3::SHAKE128::new().hash_xof(data, 16);
//! let output_16KiB: Vec<u8> = sha3::SHAKE128::new().hash_xof(data, 16 * 1024);
//! ```
//!
//! As with [Hash] above, the [XOF] trait has streaming APIs in the form of [XOF::absorb] and [XOF::squeeze].
//! Unlike [Hash::do_final], [XOF::squeeze] can be called multiple times.
//! The following code produces the same output as the previous example:
//!```
//! use core_interface::traits::XOF;
//!
//! let data: &[u8] = b"Hello, world!";
//! let mut shake = sha3::SHAKE128::new();
//! shake.absorb(data).expect("Failed to absorb data.");
//! let output_16byte: Vec<u8> = shake.squeeze(16).expect("Is infallible");
//!
//! let mut shake = sha3::SHAKE128::new();
//! let mut output_16KiB: Vec<u8> = vec![];
//! for i in 0..16 { output_16KiB.extend_from_slice(&shake.squeeze(1024).expect("Is infallible")) }
//! ```
//!
//! ## KDF
//! SHA3 offers Key Derivation Functions in the form of KDF, which is accessed through the [KDF] trait,
//! which is implemented by all SHA3 and SHAKE variants.
//! [KDF] acts on [KeyMaterialInternal] objects as both the input and output values.
//! In the case of SHA3, the [KDF] interfaces are simple wrapper functions around the underlying SHA3 or SHAKE
//! primitive that correctly maintains the length and entropy metadata of the key material that it is acting on.
//! This is intended to act as a developer ait to prevent  some classes of developer mistakes, such as
//! deriving a cryptographic key from uninitialized (aka zeroized) input key material, or using low-entropy
//! input key material to derive a MAC, symmetric, or asymmetric key.
//!
//! ```
//! use core_interface::traits::KDF;
//! use core_interface::key_material::{KeyMaterial256, KeyType};
//!
//! let input_key = KeyMaterial256::from_bytes(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F").unwrap();
//! let output_key = sha3::SHA3_256::new().derive_key(&input_key, b"Additional input").unwrap();
//!```
//! In the previous example, since [KeyMaterialInternal::from_bytes] cannot know the amount of entropy in the input data,
//! it automatically tags it as [KeyType::BytesLowEntropy], and thus [SHA3::derive_key] produces an output key
//! which also has type [KeyType::BytesLowEntropy].
//! This would also be the case even if the input had type
//! [KeyType::BytesFullEntropy] since the input [KeyMaterialInternal] is 16 bytes but [SHA3_256] needs at least 32 bytes of
//! full-entropy input key material in order to be able to produce full entropy output key material.

#![forbid(unsafe_code)]
#![allow(private_bounds)]

use crate::keccak::{KeccakDigest, KeccakSize};
use core_interface::errors::{HashError, KDFError};
use core_interface::key_material::{KeyMaterialInternal, KeyType};
use core_interface::traits::{
    Algorithm, Hash, HashAlgParams, KDF, KeyMaterial, SecurityStrength, XOF,
};
use utils::{max, min};

mod keccak;

/*** String constants ***/
pub const SHA3_224_NAME: &str = "SHA3-224";
pub const SHA3_256_NAME: &str = "SHA3-256";
pub const SHA3_384_NAME: &str = "SHA3-384";
pub const SHA3_512_NAME: &str = "SHA3-512";
pub const SHAKE128_NAME: &str = "SHAKE128";
pub const SHAKE256_NAME: &str = "SHAKE256";

/*** pub types ***/
pub type SHA3_224 = SHA3<SHA3_224Params>;
pub type SHA3_256 = SHA3<SHA3_256Params>;
pub type SHA3_384 = SHA3<SHA3_384Params>;
pub type SHA3_512 = SHA3<SHA3_512Params>;
pub type SHAKE128 = SHAKE<SHAKE128Params>;
pub type SHAKE256 = SHAKE<SHAKE256Params>;

/*** Param traits ***/
trait SHA3Params: HashAlgParams {
    const SIZE: KeccakSize;
}

// TODO: more elegant to macro this?
impl Algorithm for SHA3_224 {
    const ALG_NAME: &'static str = SHA3_224_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_112bit;
}
impl HashAlgParams for SHA3_224 {
    const OUTPUT_LEN: usize = 28;
    // const BLOCK_LEN: usize = 64;
    const BLOCK_LEN: usize = 144; // FIPS 202 Table 3
}
pub struct SHA3_224Params;
impl Algorithm for SHA3_224Params {
    const ALG_NAME: &'static str = SHA3_224_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_112bit;
}
impl HashAlgParams for SHA3_224Params {
    const OUTPUT_LEN: usize = 28;
    // const BLOCK_LEN: usize = 64;
    const BLOCK_LEN: usize = 144; // FIPS 202 Table 3
}
impl SHA3Params for SHA3_224Params {
    const SIZE: KeccakSize = KeccakSize::_224;}

impl Algorithm for SHA3_256 {
    const ALG_NAME: &'static str = SHA3_256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}
impl HashAlgParams for SHA3_256 {
    const OUTPUT_LEN: usize = 32;
    // const BLOCK_LEN: usize = 64;
    const BLOCK_LEN: usize = 136; // FIPS 202 Table 3
}
pub struct SHA3_256Params;
impl Algorithm for SHA3_256Params {
    const ALG_NAME: &'static str = SHA3_256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}
impl HashAlgParams for SHA3_256Params {
    const OUTPUT_LEN: usize = 32;
    // const BLOCK_LEN: usize = 64;
    const BLOCK_LEN: usize = 136; // FIPS 202 Table 3
}
impl SHA3Params for SHA3_256Params {
    const SIZE: KeccakSize = KeccakSize::_256;
}

pub struct SHA3_384Params;
impl Algorithm for SHA3_384 {
    const ALG_NAME: &'static str = SHA3_384_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}
impl HashAlgParams for SHA3_384 {
    const OUTPUT_LEN: usize = 48;
    // const BLOCK_LEN: usize = 128;
    const BLOCK_LEN: usize = 104; // FIPS 202 Table 3
}
impl Algorithm for SHA3_384Params {
    const ALG_NAME: &'static str = SHA3_384_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}
impl HashAlgParams for SHA3_384Params {
    const OUTPUT_LEN: usize = 48;
    // const BLOCK_LEN: usize = 128;
    const BLOCK_LEN: usize = 104; // FIPS 202 Table 3
}
impl SHA3Params for SHA3_384Params {
    const SIZE: KeccakSize = KeccakSize::_384;
}

pub struct SHA3_512Params;
impl Algorithm for SHA3_512 {
    const ALG_NAME: &'static str = SHA3_512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}
impl HashAlgParams for SHA3_512 {
    const OUTPUT_LEN: usize = 64;
    // const BLOCK_LEN: usize = 128;
    const BLOCK_LEN: usize = 72; // FIPS 202 Table 3
}
impl Algorithm for SHA3_512Params {
    const ALG_NAME: &'static str = SHA3_512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}
impl HashAlgParams for SHA3_512Params {
    const OUTPUT_LEN: usize = 64;
    // const BLOCK_LEN: usize = 128;
    const BLOCK_LEN: usize = 72; // FIPS 202 Table 3
}
impl SHA3Params for SHA3_512Params {
    const SIZE: KeccakSize = KeccakSize::_512;
}

trait SHAKEParams: Algorithm {
    const SIZE: KeccakSize;
}
pub struct SHAKE128Params;
impl Algorithm for SHAKE128Params {
    const ALG_NAME: &'static str = SHAKE128_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}
impl SHAKEParams for SHAKE128Params {
    const SIZE: KeccakSize = KeccakSize::_128;
}

pub struct SHAKE256Params;
impl Algorithm for SHAKE256Params {
    const ALG_NAME: &'static str = SHAKE256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}
impl SHAKEParams for SHAKE256Params {
    const SIZE: KeccakSize = KeccakSize::_256;
}

/*** SHA3 ***/

#[derive(Clone)]
pub struct SHA3<PARAMS: SHA3Params> {
    _params: std::marker::PhantomData<PARAMS>,
    keccak: KeccakDigest,
    kdf_key_type: KeyType,
    kdf_security_strength: SecurityStrength,
    kdf_entropy: usize,
}

// Note: don't need a zeroizing Drop here because all the sensitive info is in KeccakDigest, which has one.

impl<PARAMS: SHA3Params> SHA3<PARAMS> {
    pub fn new() -> Self {
        Self {
            _params: std::marker::PhantomData,
            keccak: KeccakDigest::new(PARAMS::SIZE),
            kdf_key_type: KeyType::Zeroized,
            kdf_security_strength: SecurityStrength::None,
            kdf_entropy: 0,
        }
    }

    /// Swallows errors and simply returns an empty Vec<u8> if the hashes fails for whatever reason.
    fn hash_internal(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.do_update(data);
        self.do_final_out(output)
    }

    fn mix_key_internal(&mut self, key: &impl KeyMaterial) {
        // track the strongest input key type
        self.kdf_key_type = *max(&self.kdf_key_type, &key.key_type());

        // track input entropy
        if key.is_full_entropy() {
            self.kdf_entropy += key.key_len();
            self.kdf_security_strength =
                max(&self.kdf_security_strength, &key.security_strength()).clone();
            self.kdf_security_strength = min(
                &self.kdf_security_strength,
                &SecurityStrength::from_bits(PARAMS::OUTPUT_LEN * 8 / 2),
            )
            .clone();
        }

        self.do_update(key.ref_to_bytes())
    }

    fn derive_key_final_internal(
        self,
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterial>, KDFError> {
        let mut output_key = KeyMaterialInternal::<64>::new();
        self.derive_key_out_final_internal(additional_input, &mut output_key)?;

        Ok(Box::new(output_key))
    }

    fn derive_key_out_final_internal(
        mut self,
        additional_input: &[u8],
        output_key: &mut impl KeyMaterial,
    ) -> Result<usize, KDFError> {
        // For the KDF to be considered "fully-seeded" and be capable of outputting full-entropy KeyMaterials,
        // it requires full-entropy input that is at least block length.
        // TODO: citation needed, which NIST spec did I get this from?
        if self.kdf_entropy < PARAMS::OUTPUT_LEN {
            self.kdf_key_type = min(&self.kdf_key_type, &KeyType::BytesLowEntropy).clone();
            self.kdf_security_strength = SecurityStrength::None; // BytesLowEntropy can't have a securtiy level.
        }

        self.do_update(additional_input);

        let mut key_type = self.kdf_key_type.clone();
        let output_security_strength = self.kdf_security_strength.clone();
        output_key.allow_hazardous_operations();
        let bytes_written = self.do_final_out(output_key.mut_ref_to_bytes()?);
        output_key.set_key_len(bytes_written)?;

        // since we've done some computation, the result will not actually be zeroized, even if all input key material was zeroized.
        if key_type == KeyType::Zeroized {
            key_type = KeyType::BytesLowEntropy;
        }
        output_key.set_key_type(key_type)?;
        output_key.set_security_strength(
            min(&output_security_strength, &SecurityStrength::from_bits(bytes_written * 8)).clone(),
        )?;
        output_key.drop_hazardous_operations();
        output_key.truncate(min(&output_key.key_len(), &PARAMS::OUTPUT_LEN).clone())?;
        Ok(bytes_written)
    }
}

impl<PARAMS: SHA3Params> Default for SHA3<PARAMS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<PARAMS: SHA3Params> Hash for SHA3<PARAMS> {
    /// As per FIPS 202 Table 3.
    /// Required, for example, to compute the pad lengths in HMAC.
    fn block_bitlen(&self) -> usize {
        PARAMS::BLOCK_LEN * 8
    }

    fn output_len(&self) -> usize {
        PARAMS::OUTPUT_LEN
    }

    fn hash(self, data: &[u8]) -> Vec<u8> {
        let mut output: Vec<u8> = vec![0u8; PARAMS::OUTPUT_LEN];
        _ = self.hash_internal(data, &mut output[..]);
        output
    }

    fn hash_out(self, data: &[u8], mut output: &mut [u8]) -> usize {
        self.hash_internal(data, &mut output)
    }

    fn do_update(&mut self, data: &[u8]) {
        self.keccak.absorb(data)
    }

    fn do_final(self) -> Vec<u8> {
        let dbg_rslt_len = self.output_len();
        let mut output: Vec<u8> = vec![0u8; self.output_len()];
        let bytes_written = self.do_final_out(output.as_mut_slice());
        debug_assert_eq!(bytes_written, dbg_rslt_len);

        output
    }

    fn do_final_out(mut self, output: &mut [u8]) -> usize {
        self.keccak.absorb_bits(0x02, 2).expect("do_final_out: keccak.absorb_bits failed."); // this shouldn't fail because by construction you can only enter this function once, and this is the only way to absorb partial bits.

        let bytes_written = if output.len() <= self.output_len() {
            self.keccak.squeeze(output)
        } else {
            let min =
                if output.len() >= self.output_len() { self.output_len() } else { output.len() };
            self.keccak.squeeze(&mut output[..min])
        };
        bytes_written
    }

    fn do_final_partial_bits(
        self,
        partial_byte: u8,
        num_partial_bits: usize,
    ) -> Result<Vec<u8>, HashError> {
        let dbg_rslt_len = self.output_len();
        let mut output: Vec<u8> = vec![0u8; self.output_len()];
        let bytes_written =
            self.do_final_partial_bits_out(partial_byte, num_partial_bits, output.as_mut_slice())?;
        debug_assert_eq!(bytes_written, dbg_rslt_len);

        Ok(output)
    }

    fn do_final_partial_bits_out(
        mut self,
        partial_byte: u8,
        num_partial_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError> {
        // Mutants note: yep, this is just bit-setting into empty space, so it doesn't matter whether it's OR or XOR.
        let mut final_input: u16 =
            ((partial_byte as u16) & ((1 << num_partial_bits) - 1)) | (0x02 << num_partial_bits);
        let mut final_bits = num_partial_bits + 2;

        if final_bits >= 8 {
            self.keccak.absorb(&[final_input as u8]);
            final_bits -= 8;
            final_input >>= 8;
        }

        self.keccak.absorb_bits(final_input as u8, final_bits)?;

        let min = if output.len() >= self.output_len() { self.output_len() } else { output.len() };
        Ok(self.keccak.squeeze(&mut output[..min]))
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::from_bytes(PARAMS::OUTPUT_LEN / 2)
    }
}

/// SHA3 is allowed to be used as a KDF in the form HASH(X) as per NIST SP 800-56C.
impl<PARAMS: SHA3Params> KDF for SHA3<PARAMS> {
    /// Returns a [KeyMaterialInternal].
    /// For the KDF to be considered "fully-seeded" and be capable of outputting full-entropy KeyMaterials,
    /// it requires full-entropy input that is at least the bit size (ie 256 bits for SHA3-256, etc).
    fn derive_key(
        mut self,
        key: &impl KeyMaterial,
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterial>, KDFError> {
        self.mix_key_internal(key);
        self.derive_key_final_internal(additional_input)
    }

    fn derive_key_out(
        mut self,
        key: &impl KeyMaterial,
        additional_input: &[u8],
        output_key: &mut impl KeyMaterial,
    ) -> Result<usize, KDFError> {
        // self.derive_key_from_multiple_out(&[key], additional_input, output_key)
        self.mix_key_internal(key);
        self.derive_key_out_final_internal(additional_input, output_key)
    }

    fn derive_key_from_multiple(
        mut self,
        keys: &[&impl KeyMaterial],
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterial>, KDFError> {
        for key in keys {
            self.mix_key_internal(*key);
        }
        self.derive_key_final_internal(additional_input)
    }

    fn derive_key_from_multiple_out(
        mut self,
        keys: &[&impl KeyMaterial],
        additional_input: &[u8],
        output_key: &mut impl KeyMaterial,
    ) -> Result<usize, KDFError> {
        // self.derive_key_from_multiple_internal(keys, additional_input, output_key)
        for key in keys {
            self.mix_key_internal(*key);
        }
        self.derive_key_out_final_internal(additional_input, output_key)
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::from_bytes(PARAMS::OUTPUT_LEN / 2)
    }
}

/*** SHAKE ***/

/// Note: FIPS 202 section 7 states:
///
///   "SHAKE128 and SHAKE256 are approved XOFs, whose approved uses will be specified in
/// NIST Special Publications. Although some of those uses may overlap with the uses of approved
/// hash functions, the XOFs are not approved as hash functions, due to the property that is
/// discussed in Sec. A.2."
///
/// Section A.2 describes how SHAKE does not internally diversify its output based on the requested length.
/// For example, the first 32 bytes of SHAKE128("message", 64) and SHAKE128("message", 128), will be identical
/// and equal to SHAKE128("message", 32). Proper hash functions don't do this, and NIST is concerned that
/// this could lead to application vulnerabilities.
///
/// As such, even though SHAKE is physically capable of acting as a hash function, and in fact is secure
/// as such if the provided message includes the requested length, SHAKE does not implement the [Hash] trait.
#[derive(Clone)]
pub struct SHAKE<PARAMS: SHAKEParams> {
    _phantomdata: std::marker::PhantomData<PARAMS>,
    keccak: KeccakDigest,
    kdf_key_type: KeyType,
    kdf_security_strength: SecurityStrength,
    kdf_entropy: usize,
}

// Note: don't need a zeroizing Drop here because all the sensitive info is in KeccakDigest, which has one.

impl<PARAMS: SHAKEParams> Algorithm for SHAKE<PARAMS> {
    const ALG_NAME: &'static str = PARAMS::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = PARAMS::MAX_SECURITY_STRENGTH;
}

impl<PARAMS: SHAKEParams> SHAKE<PARAMS> {
    pub fn new() -> Self {
        Self {
            _phantomdata: std::marker::PhantomData,
            keccak: KeccakDigest::new(PARAMS::SIZE),
            kdf_key_type: KeyType::Zeroized,
            kdf_security_strength: SecurityStrength::None,
            kdf_entropy: 0,
        }
    }

    /// Swallows errors and simply returns an empty Vec<u8> if the hashes fails for whatever reason.
    fn hash_internal(mut self, data: &[u8], result_len: usize) -> Vec<u8> {
        self.absorb(data).expect("Should be infallible.");
        self.squeeze(result_len).expect(".squeeze() should be infallible.") // This should be Infallible ... figure out a clean way to do this
    }

    fn hash_internal_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.absorb(data).expect("Should be infallible.");
        self.squeeze_out(output).expect(".squeeze_out() should be infallible.")
    }

    fn mix_key_internal(&mut self, key: &impl KeyMaterial) -> Result<(), HashError> {
        // track the strongest input key type
        self.kdf_key_type = *max(&self.kdf_key_type, &key.key_type());

        // track input entropy
        if key.is_full_entropy() {
            self.kdf_entropy += key.key_len();
            self.kdf_security_strength =
                max(&self.kdf_security_strength, &key.security_strength()).clone();
            self.kdf_security_strength =
                min(&self.kdf_security_strength, &SecurityStrength::from_bits(PARAMS::SIZE as usize))
                    .clone();
        }

        self.absorb(key.ref_to_bytes())
    }

    fn derive_key_final_internal(
        mut self,
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterial>, KDFError> {
        // It's unfortunate to return an oversized KeyMaterial most of the time, but I've had enough
        // of fighting with Rust traits for now ...
        let mut output_key = KeyMaterialInternal::<64>::new();
        self.derive_key_out_final_internal(additional_input, &mut output_key)?;

        // 128 => 32, 256 => 64
        output_key.truncate(2 * (PARAMS::SIZE as usize) / 8)?;
        Ok(Box::new(output_key))
    }

    fn derive_key_out_final_internal(
        &mut self,
        additional_input: &[u8],
        output_key: &mut impl KeyMaterial,
    ) -> Result<usize, KDFError> {
        // For the KDF to be considered "fully-seeded" and be capable of outputting full-entropy KeyMaterials,
        // it requires full-entropy input that is at least 2x the bit size (ie 256 bits for SHAKE128, and 512 bits for SHAKE256).
        // TODO: citation needed, which NIST spec did I get this from?
        // TODO: intuitivitely this makes sense since SHAKE256 and SHA3-256 are both KECCAK[512], and SHAKE128 is KECCAK[256],
        // TODO: but I would rather find an actual reference for this "fully-seeded" threshold.
        if self.kdf_entropy < 2 * (PARAMS::SIZE as usize) / 8 {
            self.kdf_key_type = min(&self.kdf_key_type, &KeyType::BytesLowEntropy).clone();
            self.kdf_security_strength = SecurityStrength::None; // BytesLowEntropy can't have a securtiy level.
        }

        self.absorb(additional_input)?;

        // let mut buf = [0u8; 64];
        output_key.allow_hazardous_operations();
        let bytes_written = self.squeeze_out(output_key.mut_ref_to_bytes().expect("We just set .allow_hazardous_operations(), so this should be fine."))?;
        output_key.set_key_len(bytes_written)?;

        // since we've done some computation, the result will not actually be zeroized, even if all input key material was zeroized.
        if self.kdf_key_type == KeyType::Zeroized {
            self.kdf_key_type = KeyType::BytesLowEntropy;
        }
        output_key.set_key_type(self.kdf_key_type)?;
        output_key.set_security_strength(
            min(&self.kdf_security_strength, &SecurityStrength::from_bits(bytes_written * 8))
                .clone(),
        )?;
        output_key.drop_hazardous_operations();
        Ok(bytes_written)
    }
}

impl<PARAMS: SHAKEParams> KDF for SHAKE<PARAMS> {
    /// Returns a [KeyMaterialInternal].
    /// For the KDF to be considered "fully-seeded" and be capable of outputting full-entropy KeyMaterials,
    /// it requires full-entropy input that is at least 2x the bit size (ie 256 bits for SHAKE128, and 512 bits for SHAKE256).
    /// Returns a 32 byte key for SHAKE128 and a 64 byte key for SHAKE256.
    /// To produce longer keys, use [derive_key_out].
    /// To produce shorter keys, either use [derive_key_out] or truncate this result down with [KeyMaterialInternal::truncate].
    fn derive_key(
        mut self,
        key: &impl KeyMaterial,
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterial>, KDFError> {
        // self.derive_key_from_multiple(&[key], additional_input)
        self.mix_key_internal(key)?;
        self.derive_key_final_internal(additional_input)
    }

    fn derive_key_out(
        mut self,
        key: &impl KeyMaterial,
        additional_input: &[u8],
        output_key: &mut impl KeyMaterial,
    ) -> Result<usize, KDFError> {
        // self.derive_key_from_multiple_out(&[key], additional_input, output)
        self.mix_key_internal(key)?;
        self.derive_key_out_final_internal(additional_input, output_key)
    }

    /// Always returns a full [KeyMaterialInternal]; ie that contains [MAX_KEY_LEN] bytes of key material.
    /// This can be truncated down with [KeyMaterialInternal::truncate].
    /// Returns a 32 byte key for SHAKE128 and a 64 byte key for SHAKE256.
    /// To produce longer keys, use [derive_key_out].
    /// To produce shorter keys, either use [derive_key_out] or truncate this result down with [KeyMaterialInternal::truncate].
    fn derive_key_from_multiple(
        mut self,
        keys: &[&impl KeyMaterial],
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterial>, KDFError> {
        for key in keys {
            self.mix_key_internal(*key)?;
        }
        self.derive_key_final_internal(additional_input)
    }

    fn derive_key_from_multiple_out(
        mut self,
        keys: &[&impl KeyMaterial],
        additional_input: &[u8],
        output_key: &mut impl KeyMaterial,
    ) -> Result<usize, KDFError> {
        for key in keys {
            self.mix_key_internal(*key)?;
        }
        self.derive_key_out_final_internal(additional_input, output_key)
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::from_bits(PARAMS::SIZE as usize)
    }
}

impl<PARAMS: SHAKEParams> Default for SHAKE<PARAMS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<PARAMS: SHAKEParams> XOF for SHAKE<PARAMS> {
    fn hash_xof(self, data: &[u8], result_len: usize) -> Vec<u8> {
        self.hash_internal(data, result_len)
    }

    fn hash_xof_out(self, data: &[u8], output: &mut [u8]) -> usize {
        self.hash_internal_out(data, output)
    }

    fn absorb(&mut self, data: &[u8]) -> Result<(), HashError> {
        Ok(self.keccak.absorb(data))
    }

    /// Switches to squeezing.
    fn absorb_last_partial_byte(
        &mut self,
        partial_byte: u8,
        num_partial_bits: usize,
    ) -> Result<(), HashError> {
        if !(1..=7).contains(&num_partial_bits) {
            return Err(HashError::InvalidLength("must be in the range [0,7]"));
        }
        // Mutants note: yep, this is just bit-setting into empty space, so it doesn't matter whether it's OR or XOR.
        let mut final_input: u16 =
            ((partial_byte as u16) & ((1 << num_partial_bits) - 1)) | (0x0F << num_partial_bits);
        let mut final_bits = num_partial_bits + 4;

        if final_bits >= 8 {
            self.keccak.absorb(&[final_input as u8]);
            final_bits -= 8;
            final_input >>= 8;
        }

        self.keccak.absorb_bits(final_input as u8, final_bits).expect("Absorb failed.");

        Ok(())
    }

    /// Is infallible.
    fn squeeze(&mut self, num_bytes: usize) -> Result<Vec<u8>, HashError> {
        let mut out: Vec<u8> = vec![0u8; num_bytes];
        self.squeeze_out(&mut out)?;
        Ok(out)
    }

    /// Is infallible.
    fn squeeze_out(&mut self, output: &mut [u8]) -> Result<usize, HashError> {
        if !self.keccak.squeezing {
            self.keccak.absorb_bits(0x0F, 4).expect("Absorb_bits failed");
        };

        Ok(self.keccak.squeeze(output))
    }

    fn squeeze_partial_byte_final(self, num_bits: usize) -> Result<u8, HashError> {
        let mut output: u8 = 0;
        self.squeeze_partial_byte_final_out(num_bits, &mut output)?;
        Ok(output)
    }

    /// Result is the number of bits squezed into `output`.
    fn squeeze_partial_byte_final_out(
        mut self,
        num_bits: usize,
        output: &mut u8,
    ) -> Result<(), HashError> {
        if !(1..=7).contains(&num_bits) {
            return Err(HashError::InvalidLength("must be in the range [0,7]"));
        }

        let mut buf = [0u8; 1];
        self.keccak.squeeze(&mut buf);
        *output = buf[0] >> 8 - num_bits;
        Ok(())
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::from_bits(PARAMS::SIZE as usize)
    }
}
