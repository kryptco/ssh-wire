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
