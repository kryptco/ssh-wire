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

#[no_mangle]
pub extern "C" fn verify_signature(
    pubkey_ptr: *const u8, pubkey_len: usize,
    sig_ptr: *const u8, sig_len: usize,
    msg_ptr: *const u8, msg_len: usize,
    ) -> bool {
    false
}


/// Expose the JNI interface for android below
#[cfg(target_os="android")]
#[allow(non_snake_case)]
pub mod android {
    extern crate jni;

    use super::*;
    use self::jni::JNIEnv;
    use self::jni::objects::{JClass, JString};
    use self::jni::sys::{jint, jlong, jboolean};
    use self::jni::strings::JNIString;

    #[no_mangle]
    pub unsafe extern "C" fn Java_co_krypt_kryptonite_protocol_HostAuth_verifySessionID(env: JNIEnv, _: JClass, pubkey : JString, signature: JString, session_id: JString) -> jboolean {
        0
    }
}
