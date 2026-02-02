use crate::DUMMY_SEED_512;
use core_interface::errors::{KeyMaterialError, MACError};
use core_interface::key_material::{KeyMaterial512, KeyType};
use core_interface::traits::MAC;
use core_interface::traits::{KeyMaterial, KeyedAlgorithm, SecurityStrength};

pub struct TestFrameworkMAC {
    // Put any config options here
}

impl TestFrameworkMAC {
    pub fn new() -> Self {
        Self {}
    }

    /// Test all the members of trait Hash against the given input-output pair.
    /// This gives good baseline test coverage, but is not exhaustive.
    pub fn test_mac<M: MAC + KeyedAlgorithm + Default>(
        &self,
        key: &impl KeyMaterial,
        input: &[u8],
        expected_output: &[u8],
    ) {
        // Test ::mac()
        match M::default().mac(key, input) {
            Ok(o) => assert_eq!(o, expected_output),
            Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => { /* fine, this one we'll ignore because some of the RFC vectors have keys that are actually too short */
            }
            Err(err) => panic!("Unexpected error: {:?}", err),
        }

        // Test ::mac_out
        let mut out = vec![0u8; expected_output.len()];
        match M::default().mac_out(key, input, &mut out) {
            Ok(o) => {
                assert_eq!(o, expected_output.len());
                assert_eq!(out, expected_output)
            }
            Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => { /* fine, this one we'll ignore because some of the RFC vectors have keys that are actually too short */
            }
            Err(err) => panic!("Unexpected error: {:?}", err),
        }

        // Test an output buffer that's too small (should truncate)
        let mut out = vec![0u8; expected_output.len() - 2];
        match M::default().mac_out(key, input, &mut out) {
            Ok(o) => {
                assert_eq!(o, expected_output.len() - 2);
                assert_eq!(out, expected_output[..expected_output.len() - 2])
            }
            Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => { /* fine, this one we'll ignore because some of the RFC vectors have keys that are actually too short */
            }
            Err(err) => panic!("Unexpected error: {:?}", err),
        }

        // Test an output buffer that's too big (expect the first L bytes to get filled)
        let mut out = vec![0u8; 2 * expected_output.len()];
        match M::default().mac_out(key, input, &mut out) {
            Ok(o) => {
                assert_eq!(o, expected_output.len());
                assert_eq!(&out[..expected_output.len()], expected_output);
                assert_eq!(&out[expected_output.len()..], vec![0u8; expected_output.len()]);
            }
            Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => { /* fine, this one we'll ignore because some of the RFC vectors have keys that are actually too short */
            }
            Err(err) => panic!("Unexpected error: {:?}", err),
        }

        // Test ::verify()
        M::default().verify(key, input, expected_output).unwrap();

        // Test .init(), .do_update(), .do_mac_final()
        // At the same time, test .output_len()
        let mut mac = M::default();
        match mac.init(key) {
            Ok(_) | Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => { /* fine, this one we'll ignore because some of the RFC vectors have keys that are actually too short */
            }
            Err(err) => panic!("Unexpected error: {:?}", err),
        }
        let output_len = mac.output_len();
        mac.do_update(input).unwrap();
        let out = mac.do_final().unwrap();
        assert_eq!(out, expected_output);

        // Test .output_len()
        assert_eq!(output_len, out.len());

        // Test .init(), .do_update(), .do_mac_final_out()
        let mut mac = M::default();
        match mac.init(key) {
            Ok(_) | Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => { /* fine, this one we'll ignore because some of the RFC vectors have keys that are actually too short */
            }
            Err(err) => panic!("Unexpected error: {:?}", err),
        }
        mac.do_update(input).unwrap();
        let mut out = vec![0u8; mac.output_len()];
        let out_len = mac.do_final_out(&mut *out).unwrap();
        assert_eq!(out, expected_output);
        assert_eq!(out_len, out.len());

        // Test .init(), .do_update(), .do_verify_final_out()
        let mut mac = M::default();
        match mac.init(key) {
            Ok(_) | Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => { /* fine, this one we'll ignore because some of the RFC vectors have keys that are actually too short */
            }
            Err(err) => panic!("Unexpected error: {:?}", err),
        }
        mac.do_update(input).unwrap();
        mac.do_verify_final(expected_output).unwrap();

        // Error case: test uninitialized do_update
        let mut mac = M::default();
        // mac.init(key).unwrap();
        let _ = match mac.do_update(input) {
            Ok(_) => {
                panic!("Should not have returned a MACError::InvalidState, but it passed");
            }
            Err(MACError::InvalidState(_)) => { /*** good ***/ }
            Err(_) => panic!(
                "Should not have returned a MACError::InvalidState, but it returned something else"
            ),
        };

        // Error case: test uninitialized do_final
        let mac = M::default();
        // mac.init(key).unwrap();
        // mac.do_update(input).unwrap();
        let _ = match mac.do_final() {
            Ok(_) => {
                panic!("Should not have returned a MACError::InvalidState, but it passed");
            }
            Err(MACError::InvalidState(_)) => { /*** good ***/ }
            Err(_) => panic!(
                "Should not have returned a MACError::InvalidState, but it returned something else"
            ),
        };

        // entropy of input key

        // MACs of all security strengths should throw an error on a no-security key.

        let mut key_none =
            KeyMaterial512::from_bytes_as_type(&DUMMY_SEED_512[0..64], KeyType::MACKey).unwrap();
        key_none.set_security_strength(SecurityStrength::None).unwrap();
        match M::default().mac_out(&key_none, input, &mut out) {
            Ok(_) | Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => { /* fine */
            }
            Err(_other_error) => { /* handle error */ }
        }

        let mut low_security_key =
            KeyMaterial512::from_bytes_as_type(&DUMMY_SEED_512[..64], KeyType::MACKey).unwrap();
        low_security_key.allow_hazardous_operations();
        match M::default().max_security_strength() {
            SecurityStrength::None => {
                low_security_key.truncate(13).unwrap();
                low_security_key.set_security_strength(SecurityStrength::None).unwrap();
            }
            SecurityStrength::_112bit => {
                low_security_key.truncate(28).unwrap();
                low_security_key.set_security_strength(SecurityStrength::None).unwrap();
            }
            SecurityStrength::_128bit => {
                low_security_key.truncate(32).unwrap();
                low_security_key.set_security_strength(SecurityStrength::_112bit).unwrap();
            }
            SecurityStrength::_192bit => {
                low_security_key.truncate(48).unwrap();
                low_security_key.set_security_strength(SecurityStrength::_128bit).unwrap();
            }
            SecurityStrength::_256bit => {
                low_security_key.truncate(64).unwrap();
                low_security_key.set_security_strength(SecurityStrength::_192bit).unwrap();
            }
        };
        low_security_key.drop_hazardous_operations();

        // init
        assert!(low_security_key.security_strength() < M::default().max_security_strength());
        let mut hmac = M::default();
        // complains at first
        match hmac.init(&low_security_key) {
            Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => { /* fine */ }
            _ => {
                panic!(
                    "This should have thrown a KeyMaterialError::SecurityStrength error but it didn't"
                )
            }
        }
        // but fine if you set .allow_weak_keys()
        hmac.allow_weak_keys();
        hmac.init(&low_security_key).unwrap();
        hmac.do_update(b"Hi There").unwrap();
        hmac.do_final().unwrap();

        // one-shot APIs
        // complains at first
        match M::default().mac(&low_security_key, b"Hi There") {
            Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => { /* fine */ }
            _ => {
                panic!(
                    "This should have thrown a KeyMaterialError::SecurityStrength error but it didn't"
                )
            }
        }
        // but fine if you set .allow_weak_keys()
        let mut mac = M::default();
        mac.allow_weak_keys();
        let out1 = mac.mac(&low_security_key, b"Hi There").unwrap();
        let output_len = M::default().output_len();
        assert_eq!(out1.len(), output_len);

        let mut out2 = [0u8; 64];
        // complains at first
        match M::default().mac_out(&low_security_key, b"Hi There", &mut out2) {
            Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => { /* fine */ }
            _ => {
                panic!(
                    "This should have thrown a KeyMaterialError::SecurityStrength error but it didn't"
                )
            }
        }
        // but fine if you set .allow_weak_keys()
        let mut mac = M::default();
        mac.allow_weak_keys();
        let bytes_written = mac.mac_out(&low_security_key, b"Hi There", &mut out2).unwrap();
        assert_eq!(bytes_written, output_len);
        assert_eq!(out1, out2[..out1.len()]);
        M::default().verify(&low_security_key, b"Hi There", &out2[..output_len]).unwrap();
    }
}
