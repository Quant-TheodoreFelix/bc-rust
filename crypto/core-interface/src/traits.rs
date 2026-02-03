//! Provides simplified abstracted APIs over classes of cryptigraphic primitives, such as Hash, KDF, etc.

use crate::errors::{HashError, KDFError, KeyMaterialError, MACError, RNGError};

// Imports needed for docs
#[allow(unused_imports)]
use crate::key_material::KeyMaterialInternal;
#[allow(unused_imports)]
use crate::key_material::KeyType;
// end of imports needed for docs

pub trait Algorithm {
    const ALG_NAME: &'static str;
    const MAX_SECURITY_STRENGTH: SecurityStrength;
}

pub trait Hash {
    /// The size of the internal block in bits -- needed by functions such as HMAC to compute security parameters.
    fn block_bitlen(&self) -> usize;

    /// The size of the output in bytes.
    fn output_len(&self) -> usize;

    /// A static one-shot API that hashes the provided data.
    /// `data` can be of any length, including zero bytes.
    fn hash(self, data: &[u8]) -> Vec<u8>;

    /// A static one-shot API that hashes the provided data into the provided output slice.
    /// `data` can be of any length, including zero bytes.
    /// The return value is the number of bytes written.
    fn hash_out(self, data: &[u8], output: &mut [u8]) -> usize;

    /// Provide a chunk of data to be absorbed into the hashes.
    /// `data` can be of any length, including zero bytes.
    /// do_update() is intended to be used as part of a streaming interface, and so may by called multiple times.
    // fn do_update(&mut self, data: &[u8]) -> Result<(), HashError>;
    fn do_update(&mut self, data: &[u8]);

    /// Finish absorbing input and produce the hashes output.
    /// Consumes self, so this must be the final call to this object.
    // fn do_final(self) -> Result<Vec<u8>, HashError>;
    fn do_final(self) -> Vec<u8>;

    /// Finish absorbing input and produce the hashes output.
    /// Consumes self, so this must be the final call to this object.
    /// will be placed in the first [Hash::output_len] bytes.
    /// The return value is the number of bytes written.
    fn do_final_out(self, output: &mut [u8]) -> usize;

    /// The same as [Hash::do_final], but allows for supplying a partial byte as the last input.
    /// Assumes that the input is in the least significant bits (big endian).
    fn do_final_partial_bits(
        self,
        partial_byte: u8,
        num_partial_bits: usize,
    ) -> Result<Vec<u8>, HashError>;

    /// The same as [Hash::do_final_out], but allows for supplying a partial byte as the last input.
    /// Assumes that the input is in the least significant bits (big endian).
    /// will be placed in the first [Hash::output_len] bytes.
    /// The return value is the number of bytes written.
    fn do_final_partial_bits_out(
        self,
        partial_byte: u8,
        num_partial_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError>;

    /// Returns the maximum security strength that this KDF is capable of supporting, based on the underlying primitives.
    fn max_security_strength(&self) -> SecurityStrength;
}

pub trait HashAlgParams: Algorithm {
    const OUTPUT_LEN: usize;
    const BLOCK_LEN: usize;
}

pub trait KDF {
    /// Implementers of this function are capable of deriving an output key from an input key,
    /// assuming that they have been properly initialized.
    ///
    /// # Entropy Conversion rules
    /// Implementations SHOULD act on a KeyMaterial of any [KeyType] and will generally
    /// return a KeyMaterial of the same type
    ///
    /// ex.:
    ///
    ///   * [KeyType::BytesLowEntropy] -> [KeyType::BytesLowEntropy])
    ///   * [KeyType::BytesFullEntropy] -> [KeyType::BytesFullEntropy])
    ///   * [KeyType::SymmetricCipherKey] -> [KeyType::SymmetricCipherKey])
    ///
    /// If provided with an input key, even if it is [KeyType::BytesFullEntropy], but that
    /// contains less key material than the internal block size of the KDF, then the KDF
    /// will not be considered properly seeded, and the output [KeyMaterialInternal] will be set to
    /// [KeyType::BytesLowEntropy] -- for example, seeding SHA3-256 with a [KeyMaterialInternal] containing
    /// only 128 bits of key material.
    ///
    /// An implement can, and in most cases SHOULD, return a [HashError] if provided
    /// with a [KeyMaterialInternal] of type [KeyType::Zeroized].
    ///
    /// # Additional Input
    /// The `additional_input` parameter is used in deriving the key, but is not credited with any entropy,
    /// and therefore does not affect the type of the output [KeyMaterialInternal].
    /// This corresponds directly to `FixedInfo` as defined in NIST SP 800-56C.
    /// The `additional_input` parameter can be empty by passing in `&[0u8; 0]`.
    ///
    /// Output length: this function will create a KeyMaterial populated with the default output length
    /// of the underlying hash primitive.
    fn derive_key(
        self,
        key: &impl KeyMaterial,
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterial>, KDFError>;

    /// Same as [KDF::derive_key], but fills the provided output [KeyMaterialInternal].
    ///
    /// Output length: this function will behave differently depending on the underlying hash primitive;
    /// some, such as SHA2 or SHA3 will produce a fixed-length output, while others, such as SHAKE or HKDF,
    /// will fill the provided KeyMaterial to capacity and require you to truncate it afterwards either manually
    /// or by using [KeyMaterial::truncate].
    fn derive_key_out(
        self,
        key: &impl KeyMaterial,
        additional_input: &[u8],
        output_key: &mut impl KeyMaterial,
    ) -> Result<usize, KDFError>;

    /// Meant to be used for hybrid key establishment schemes or other spit-key scenarios.
    /// Outputs a [KeyType::BytesFullEntropy] key whenever any one of
    /// the input keys is a [KeyType::BytesFullEntropy] key (ie full entropy).
    ///
    /// This function can also be used to mix a KeyMaterial of low entropy with one of full entropy to
    /// produce a new full entropy key. For the purposes of determining whether enough input key material
    /// was provided, the lengths of all input keys are added together.
    ///
    /// Implementations that are not safe to be used as a split-key PRF MAY still implement this function
    /// and return a result, but SHOULD set the entropy level of the returned key appropriately; for example
    /// a KDF that is only full-entropy when keyed in the first input SHOULD return a full entropy key
    /// only if the first input is full entropy.
    ///
    /// Implementations can, and in most cases SHOULD, return a [KeyMaterialInternal] of the same type as the
    /// strongest key, and SHOULD throw a [HashError] if all input keys are zeroized.
    ///
    /// Output length: this function will create a KeyMaterial populated with the default output length
    /// of the underlying hash primitive.
    fn derive_key_from_multiple(
        self,
        keys: &[&impl KeyMaterial],
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterial>, KDFError>;

    /// Same as [KDF::derive_key], but fills the provided output [KeyMaterialInternal].
    ///
    /// Output length: this function will behave differently depending on the underlying hash primitive;
    /// some, such as SHA2 or SHA3 will produce a fixed-length output, while others, such as SHAKE or HKDF,
    /// will fill the provided KeyMaterial to capacity and require you to truncate it afterwards either manually
    /// or by using [KeyMaterial::truncate].
    fn derive_key_from_multiple_out(
        self,
        keys: &[&impl KeyMaterial],
        additional_input: &[u8],
        output_key: &mut impl KeyMaterial,
    ) -> Result<usize, KDFError>;

    /// Returns the maximum security strength that this KDF is capable of supporting, based on the underlying primitives.
    fn max_security_strength(&self) -> SecurityStrength;
}

// todo -- remove?
// pub trait KeyedAlgorithm {
//     /// Configure this object to perform its operations without regard for the [SecurityStrength]
//     /// metadata on the input key. This is, for example, how you tell the library that you really
//     /// are intending to use an all-zero seed or salt, or that you are intending to use a key that
//     /// would normally be considered too short for the given algorithm.
//     ///
//     /// The reason for having this as an explicit opt-in is that while these are legitimate
//     /// use cases, they are also indistinguishable from security bugs that result from non-initialized
//     /// keys, or users providing keys that are not suitable for the given algorithm.
//     /// The intention of this flag is not to prevent developers from doing what they need to, but
//     /// rather to make them think it through carefully and tag their code where they wish to disable
//     /// security functionality of the library.
//     ///
//     /// Since this function removes one of the core security enforcement mechanisms of the library,
//     /// it should be used carefully.
//     /// Presence of this function in application code should be a sign that this code requires careful
//     /// code review.
//     fn allow_weak_keys(&mut self);
// }

/// A helper class used across the bc-rust library to hold bytes-like key material.
/// See [KeyMaterialInternal] for for details, such as constructors.
pub trait KeyMaterial {
    /// Loads the provided data into a new KeyMaterial of the specified type.
    /// This is discouraged unless the caller knows the provenance of the data, such as loading it
    /// from a cryptographic private key file.
    /// It will detect if you give it all-zero source data and set the key type to [KeyType::Zeroized] instead.
    /// Since this zeroizes and resets the key material, this is considered a dangerous conversion.
    ///
    /// The only hazardous operation here that requires setting [KeyMaterial::allow_hazardous_operations] is giving it
    /// an all-zero key, which is checked as a courtesy to catch mistakes of feeding an initialized buffer
    /// instead of an actual key. See the note on [KeyMaterialInternal::set_bytes_as_type] for suggestions
    /// for handling this.
    fn set_bytes_as_type(
        &mut self,
        source: &[u8],
        key_type: KeyType,
    ) -> Result<(), KeyMaterialError>;

    /// Get a reference to the underlying key material bytes.
    ///
    /// By reading the key bytes out of the [KeyMaterial] object, you lose the protections that it offers,
    /// however, this does not require [KeyMaterial::allow_hazardous_operations] in the name of API ergonomics:
    /// setting [KeyMaterial::allow_hazardous_operations] requires a mutable reference and reading the bytes
    /// is not an operation that should require mutability.
    fn ref_to_bytes(&self) -> &[u8];

    /// Get a mutable reference to the underlying key material bytes so that you can read or write
    /// to the underlying bytes without needing to create a temporary buffer, especially useful in
    /// cases where the required size of that buffer may be tricky to figure out at compile-time.
    /// This requires [KeyMaterial::allow_hazardous_operations] to be set.
    /// When writing directly to the buffer, you are responsible for setting the key_len and key_type afterwards,
    /// and you should [KeyMaterial::drop_hazardous_operations].
    fn mut_ref_to_bytes(&mut self) -> Result<&mut [u8], KeyMaterialError>;

    /// The size of the internal buffer; ie the largest key that this instance can hold.
    /// Equivalent to the <KEY_LEN> constant param this object was created with.
    fn capacity(&self) -> usize;

    /// Length of the key material in bytes.
    fn key_len(&self) -> usize;

    /// Requires [KeyMaterial::allow_hazardous_operations].
    fn set_key_len(&mut self, key_len: usize) -> Result<(), KeyMaterialError>;

    fn key_type(&self) -> KeyType;

    /// Requires [KeyMaterial::allow_hazardous_operations].
    fn set_key_type(&mut self, key_type: KeyType) -> Result<(), KeyMaterialError>;

    /// Security Strength, as used here, aligns with NIST SP 800-90A guidance for random number generation,
    /// specifically section 8.4.
    ///
    /// The idea is to be able to track for cryptographic seeds and bytes-like key objects across the entire library,
    /// the instatiated security level of the RNG that generated it, and whether it was handled by any intermediate
    /// objects, such as Key Derivation Functions, that have a smaller internal security level and therefore result in
    /// downgrading the security level of the key material.
    ///
    /// Note that while security strength is closely related to entropy, it is a property of the algorithms
    /// that touched the key material and not of the key material data itself, and therefore it is
    /// tracked independantly from key length and entropy level / key type.
    fn security_strength(&self) -> SecurityStrength;

    /// Requires [KeyMaterial::allow_hazardous_operations] to raise the security strength, but not to lower it.
    /// Throws [KeyMaterialError::HazardousOperationNotPermitted] on a request to raise the security level without
    /// [KeyMaterial::allow_hazardous_operations] set.
    /// Throws [KeyMaterialError::InvalidLength] on a request to set the security level higher than the current key length.
    fn set_security_strength(&mut self, strength: SecurityStrength)
    -> Result<(), KeyMaterialError>;

    /// Sets this instance to be able to perform potentially hazardous conversions such as
    /// casting a KeyMaterial of type RawUnknownEntropy or RawLowEntropy into RawFullEntropy or SymmetricCipherKey,
    /// or manually setting the key bytes via [KeyMaterial::mut_ref_to_bytes], which then requires you to be responsible
    /// for setting the key_len and key_type afterwards.
    ///
    /// The purpose of the hazardous_conversions guard is not to prevent the user from accessing their data,
    /// but rather to make the developer think carefully about the operation they are about to perform,
    /// and to give static analysis tools an obvious marker that a given KeyMaterial variable warrants
    /// further inspection.
    fn allow_hazardous_operations(&mut self);

    /// Resets this instance to not be able to perform potentially hazardous conversions.
    fn drop_hazardous_operations(&mut self);

    /// Sets the key_type of this KeyMaterial object.
    /// Does not perform any operations on the actual key material, other than changing the key_type field.
    /// If allow_hazardous_operations is true, this method will allow conversion to any KeyType, otherwise
    /// checking is performed to ensure that the conversion is "safe".
    /// This drops the allow_hazardous_operations flag, so if you need to do multiple hazardous conversions
    /// on the same instance, then you'll need to call .allow_hazardous_operations() each time.
    fn convert_key_type(&mut self, new_key_type: KeyType) -> Result<(), KeyMaterialError>;

    fn is_full_entropy(&self) -> bool;

    fn zeroize(&mut self);

    /// Is simply an alias to [KeyMaterial::set_key_len], however, this does not require [KeyMaterial::allow_hazardous_operations]
    /// since truncation is a safe operation.
    /// If truncating below the current security strength, the security strength will be lowered accordingly.
    fn truncate(&mut self, new_len: usize) -> Result<(), KeyMaterialError>;

    /// Adds the other KeyMaterial into this one, assuming there is space.
    /// Does not require [KeyMaterial::allow_hazardous_operations].
    /// Throws [KeyMaterialError::InvalidLength] if this object does not have enough space to add the other one.
    /// The resulting [KeyType] and security strength will be the lesser of the two keys.
    /// In other words, concatenating two 128-bit full entropy keys generated at a 128-bit DRBG security level
    /// will result in a 256-bit full entropy key still at the 128-bit DRBG security level.
    /// Concatenating a full entropy key with a low entropy key will result in a low entropy key.
    ///
    /// Returns the new key_len.
    fn concatenate(&mut self, other: &dyn KeyMaterial) -> Result<usize, KeyMaterialError>;

    /// Perform a constant-time comparison between the two key material buffers,
    /// ignoring differences in capacity, [KeyType], [SecurityStrength], etc.
    fn equals(&self, other: &dyn KeyMaterial) -> bool;
}

/// A Message Authentication Code algorithm is a keyed hash function that behaves somewhat like a symmetric signature function.
/// A MAC algorithm takes in a key and some data, and produces a MAC (message authentication code) that
/// can be used to verify the integrity of data.
///
/// This trait provides one-shot functions [MAC::mac], [MAC::mac_out], and [MAC::verify].
/// It also provides streaming functions [MAC::init], [MAC::do_update], [MAC::do_final], [MAC::do_final_out],
/// and [MAC::do_verify_final].
/// The workflow is that a MAC object is initialized with a key with [MAC::init], then data is
/// processed into one or more calls to [MAC::do_update],
/// after that the object can either create a MAC with [MAC::do_final] or [MAC::do_final_out] (which are final functions, and so consume the object),
/// or the object can be used to verify a MAC.
///
/// For varifying an existing MAC, it is functionally equivalent to use the provided [MAC::verify] and [MAC::do_verify_final]
/// function or to compute a new MAC and compare it to the existing MAC, however the provided verification functions
/// use constant-time comparison to avoid cryptographic timing attacks whereby an attacker could learn
/// the bytes of the MAC value under some conditions. Therefore, it is highly recommended to use the provided verification functions.
///
/// Note that the MAC key is not represented in this trait because it is provided to the MAC algorithm
/// as part of its new functions.
pub trait MAC: Sized {

    /// Create a new MAC instance with the given key.
    ///
    /// This is a common constructor whether creating or verifying a MAC value.
    ///
    /// Key / Salt is optional, which is indicated by providing an uninitialized KeyMaterial object of length zero,
    /// the capacity is irrelevant, so KeyMateriol256::new() or KeyMaterial_internal::<0>::new() would both count as an absent salt.
    ///
    /// # Note about the security strength of the provided key:
    /// If you initialize the MAC with a key that is tagged at a lower [SecurityStrength] than the
    /// underlying hash function then [MAC::new] will fail with the following error:
    /// ```text
    /// MACError::KeyMaterialError(KeyMaterialError::SecurityStrength("HMAC::init(): provided key has a lower security strength than the instantiated HMAC")
    /// ```
    /// There are situations in which it is completely reasonable and secure to provide low-entropy
    /// (and sometimes all-zero) keys / salts; for these cases we have provided [MAC::new_allow_weak_key].
    fn new(key: &impl KeyMaterial) -> Result<Self, MACError>;

    /// Create a new HMAC instance with the given key.
    ///
    /// This constructor completely ignores the [SecurityStrength] tag on the input key and will "just work".
    /// This should be used if you really do need to use a weak key, such as an all-zero salt,
    /// but use of this constructor is discouraged and you should really be asking yourself why you need it;
    /// in most cases it indicates that your key is not long enough to support the security level of this
    /// HMAC instance, or the key was derived using algorithms at a lower security level, etc.
    fn new_allow_weak_key(key: &impl KeyMaterial) -> Result<Self, MACError>;

    /// The size of the output in bytes.
    fn output_len(&self) -> usize;

    /// One-shot API that computes a MAC for the provided data.
    /// `data` can be of any length, including zero bytes.
    ///
    /// Note about the security strength of the provided key:
    /// If the provided key is tagged at a lower [SecurityStrength] than the instantiated MAC algorithm,
    /// this will fail with an error:
    /// ```text
    /// MACError::KeyMaterialError(KeyMaterialError::SecurityStrength("HMAC::init(): provided key has a lower security strength than the instantiated HMAC")
    /// ```
    fn mac(self, data: &[u8]) -> Vec<u8>;

    /// One-shot API that computes a MAC for the provided data and writes it into the provided output slice.
    /// `data` can be of any length, including zero bytes.
    ///
    /// Depending on the underlying MAC implementation, NIST may require that the library enforce
    /// a minimum length on the mac output value. See documentation for the underlying implementation
    /// to see conditions under which it throws [MACError::InvalidLength].
    fn mac_out(self, data: &[u8],out: &mut [u8]) -> Result<usize, MACError>;

    /// One-shot API that verifies a MAC for the provided data.
    /// `data` can be of any length, including zero bytes.
    ///
    /// Internally, this will re-compute the MAC value and then compare it to the provided mac value
    /// using constant-time comparison. It is highly encouraged to use this utility function instead of
    /// comparing mac values for equality yourself.
    ///
    /// Returns a bool to indicate successful verification of the provided mac value.
    /// The provided mac value must be an exact match, including length; for example a mac value
    /// which has been truncated, or which contains extra bytes at the end is considered to not be a match
    /// and will return false.
    fn verify(self, data: &[u8], mac: &[u8]) -> bool;

    /// Provide a chunk of data to be absorbed into the MAC.
    /// `data` can be of any length, including zero bytes.
    /// do_update() is intended to be used as part of a streaming interface, and so may by called multiple times.
    fn do_update(&mut self, data: &[u8]);

    fn do_final(self) -> Vec<u8>;

    /// Depending on the underlying MAC implementation, NIST may require that the library enforce
    /// a minimum length on the mac output value. See documentation for the underlying implementation
    /// to see conditions under which it throws [MACError::InvalidLength].
    fn do_final_out(self, out: &mut [u8]) -> Result<usize, MACError>;

    /// Internally, this will re-compute the MAC value and then compare it to the provided mac value
    /// using constant-time comparison. It is highly encouraged to use this utility function instead of
    /// comparing mac values for equality yourself.
    ///
    /// Returns a bool to indicate successful verification of the provided mac value.
    /// The provided mac value must be an exact match, including length; for example a mac value
    /// which has been truncated, or which contains extra bytes at the end is considered to not be a match
    /// and will return false.
    fn do_verify_final(self, mac: &[u8]) -> bool;

    /// Returns the maximum security strength that this KDF is capable of supporting, based on the underlying primitives.
    fn max_security_strength(&self) -> SecurityStrength;
}

#[derive(Eq, PartialEq, PartialOrd, Clone, Debug)]
pub enum SecurityStrength {
    None,
    _112bit,
    _128bit,
    _192bit,
    _256bit,
}

impl SecurityStrength {
    /// Rounds down to the closest supported security strength.
    /// For example, 120-bits is rounded down to 112-bit.
    pub fn from_bits(bits: usize) -> Self {
        if bits < 112 {
            Self::None
        } else if bits < 128 {
            Self::_112bit
        } else if bits < 192 {
            Self::_128bit
        } else if bits < 256 {
            Self::_192bit
        } else {
            Self::_256bit
        }
    }

    pub fn from_bytes(bytes: usize) -> Self {
        Self::from_bits(bytes * 8)
    }

    pub fn as_int(&self) -> u32 {
        match self {
            Self::None => 0,
            Self::_112bit => 112,
            Self::_128bit => 128,
            Self::_192bit => 192,
            Self::_256bit => 256,
        }
    }
}

/// An interface for random number generation.
/// This interface is meant to be simpler and more ergonomic than the interfaces provided by the
/// `rng` crate, but that one should
/// be used by applications that intend to submit to FIPS certification as it more closely aligns with the
/// requirements of SP 800-90A.
/// Note: this interface produces bytes. If you want a [KeyMaterial], then use [KeyMaterialInternal::from_rng].
pub trait RNG {
    // TODO: add back once we figure out streaming interaction with entropy sources.
    // fn add_seed_bytes(&mut self, additional_seed: &[u8]) -> Result<(), RNGError>;

    fn add_seed_keymaterial(&mut self, additional_seed: impl KeyMaterial) -> Result<(), RNGError>;
    fn next_int(&mut self) -> Result<u32, RNGError>;

    /// Returns the number of requested bytes.
    fn next_bytes(&mut self, len: usize) -> Result<Vec<u8>, RNGError>;

    /// Returns the number of bytes written.
    fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError>;

    fn fill_keymaterial_out(&mut self, out: &mut impl KeyMaterial) -> Result<usize, RNGError>;

    /// Returns the Security Strength of this RNG.
    fn security_strength(&self) -> SecurityStrength;
}

/// Extensible Output Functions (XOFs) are similar to hash functions, except that they can produce output of arbitrary length.
/// The naming used for the functions of this trait are borrowed from the SHA3-style sponge constructions that split XOF operation
/// into two phases: an absorb phase in which an arbitrary amount of input is provided to the XOF,
/// and then a squeeze phase in which an arbitrary amount of output is extracted.
/// Once squeezing begins, no more input can be absorbed.
///
/// XOFs are _similar to_ hash functions, but are not hash functions for one technical but important reason:
/// since the amount of output to produce is not provided to the XOF in advance, it cannot be used to
/// diversify the XOF output streams.
/// In other words, the overlapping parts of their outputs will be the same!
/// For example, consider two XOFs that absorb the same input data, one that is squeezed to produce 32 bytes,
/// and the other to produce 1 kb; both outputs will be identical in their first 32 bytes.
/// This could lead to loss of security in a number of ways, for example distinguishing attacks where
/// it is sufficient for the attacker to know that two values came from the same input, even if the
/// attacker cannot learn what that input was. This is attack is often sufficient, for example,
/// to break anonymity-preserving technology.
/// Applications that require the arbitrary-length output of an XOF, but also care about these
/// distinguishing attacks should consider adding a cryptographic salt to diversify the inputs.
pub trait XOF {
    /// A static one-shot API that digests the input data and produces `result_len` bytes of output.
    fn hash_xof(self, data: &[u8], result_len: usize) -> Vec<u8>;

    /// A static one-shot API that digests the input data and produces `result_len` bytes of output.
    /// Fills the provided output slice.
    fn hash_xof_out(self, data: &[u8], output: &mut [u8]) -> usize;

    fn absorb(&mut self, data: &[u8]) -> Result<(), HashError>;

    /// Switches to squeezing.
    fn absorb_last_partial_byte(
        &mut self,
        partial_byte: u8,
        num_partial_bits: usize,
    ) -> Result<(), HashError>;

    /// Can be called multiple times.
    fn squeeze(&mut self, num_bytes: usize) -> Result<Vec<u8>, HashError>;

    /// Can be called multiple times.
    /// Fills the provided output slice.
    fn squeeze_out(&mut self, output: &mut [u8]) -> Result<usize, HashError>;

    /// Squeezes a partial byte from the XOF.
    /// Output will be in the top `num_bits` bits of the returned u8 (ie Big Endian).
    /// This is a final call and consumes self.
    fn squeeze_partial_byte_final(self, num_bits: usize) -> Result<u8, HashError>;

    fn squeeze_partial_byte_final_out(
        self,
        num_bits: usize,
        output: &mut u8,
    ) -> Result<(), HashError>;

    /// Returns the maximum security strength that this KDF is capable of supporting, based on the underlying primitives.
    fn max_security_strength(&self) -> SecurityStrength;
}
