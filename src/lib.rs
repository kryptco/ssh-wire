extern crate serde;
#[macro_use]
extern crate serde_derive;

extern crate byteorder;
extern crate ring;
extern crate untrusted;
extern crate base64;
extern crate libc;

pub mod der;
pub mod serde_de;
pub mod mpint;
pub mod ecdsa;
pub mod ssh;
pub mod ed25519;

#[no_mangle]
    pub extern "C" fn kr_verify_signature(
    pubkey_ptr: *const u8, pubkey_len: usize,
    sig_ptr: *const u8, sig_len: usize,
    msg_ptr: *const u8, msg_len: usize,
    ) -> u8 {
    use std::slice::from_raw_parts;
    let pubkey_bytes = unsafe { from_raw_parts(pubkey_ptr, pubkey_len) };
    let sig_bytes = unsafe { from_raw_parts(sig_ptr, sig_len) };
    let msg_bytes = unsafe { from_raw_parts(msg_ptr, msg_len) };
    match verify_signature(pubkey_bytes, sig_bytes, msg_bytes) {
        true => 1,
        false => 0,
    }
}

pub fn verify_signature(pubkey: &[u8], sig: &[u8], msg: &[u8]) -> bool {
    use ssh::*;
    use ed25519::*;
    use ecdsa::*;
    let pk_header = match serde_de::from_slice::<PublicKeyHeader>(pubkey) {
        Ok(pk) => pk,
        _ => return false,
    };
    match pk_header._type.as_ref() {
        "ssh-rsa" => {
            match serde_de::from_slice::<RSAPublicKey>(pubkey) {
                Ok(rsa_pk) => {
                    let sig = match serde_de::from_slice::<RSASignature>(sig) {
                        Ok(sig) => sig,
                        _ => return false,
                    };
                    return rsa_pk.verify(&sig, msg);
                }
                _ => return false,
            }
        },
        "ssh-ed25519" => {
            match serde_de::from_slice::<Ed25519PublicKey>(pubkey) {
                Ok(pk) => {
                    let sig = match serde_de::from_slice::<Ed25519Signature>(sig) {
                        Ok(sig) => sig,
                        _ => return false,
                    };
                    return pk.verify(&sig, msg);
                }
                _ => return false,
            }
        },
        "ecdsa-sha2-nistp256" => {
            let pk = match serde_de::from_slice::<ECDSAPublicKey>(pubkey) {
                Ok(pk_wrapper) => {
                    match ECDSASha2Nistp256PublicKey::x962_uncompressed(&pk_wrapper.public_key) {
                        Ok(pk) => pk,
                        _ => return false,
                    }
                },
                _ => return false,
            };
            let sig = match serde_de::from_slice::<Signature>(sig) {
                Ok(sig) => {
                    match serde_de::from_slice::<ECCurvePoint>(&sig.blob) {
                        Ok(sig) => sig,
                        _ => return false,
                    }
                },
                _ => return false,
            };
            return pk.verify(&sig, msg);
        },
        _ => return false,
    };
}

/// Expose the JNI interface for android below
#[cfg(target_os="android")]
#[allow(non_snake_case)]
pub mod android {
    extern crate jni;

    use super::*;
    use self::jni::JNIEnv;
    use self::jni::objects::{JClass, JString};
    use self::jni::sys::jboolean;
    use std::ffi::CStr;

    fn b64_jstring_to_bytes(env: &JNIEnv, s: JString) -> Option<Vec<u8>> {
        let jni_string = match env.get_string(s) {
            Ok(s) => s,
            _ => return None,
        };
        let c_str = unsafe { CStr::from_ptr(jni_string.as_ptr()) };
        let bytes = match base64::decode(
            match c_str.to_str() {
                Ok(s) => s,
                _ => return None,
            }
            ) {
            Ok(b) => b,
            _ => return None,
        };
        Some(bytes)
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_co_krypt_kryptonite_protocol_HostAuth_verifySessionID(env: JNIEnv, _: JClass, pubkey : JString, signature: JString, session_id: JString) -> jboolean {
        let pk_bytes = match b64_jstring_to_bytes(&env, pubkey) {
            Some(bytes) => bytes,
            _ => return 0,
        };

        let sig_bytes = match b64_jstring_to_bytes(&env, signature) {
            Some(bytes) => bytes,
            _ => return 0,
        };
        

        let session_id_bytes = match b64_jstring_to_bytes(&env, session_id) {
            Some(bytes) => bytes,
            _ => return 0,
        };

        if verify_signature(&pk_bytes, &sig_bytes, &session_id_bytes) {
            1
        } else {
            0
        }
    }
}
