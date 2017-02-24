use der::*;

use std::fmt;
use std::convert::AsRef;

use serde::de;
use serde::de::{Deserialize,Deserializer};

//  Non-negative multi-precision integers in the SSH wire protocol begin with a \x00 byte to
//  distinguish from negative. Some libraries like ring expect do not expect a leading \x00 byte,
//  causing length checks to fail.
#[derive(Debug)]
pub struct MPUint {
    be_bytes: Vec<u8>,
}

impl AsRef<Vec<u8>> for MPUint {
    fn as_ref(&self) -> &Vec<u8> {
        &self.be_bytes
    }
}

impl MPUint {
    pub fn to_der(&self) -> Vec<u8> {
        let INTEGER_TAG : u8 = 2;
        let mut der_out = vec![INTEGER_TAG];
        if self.be_bytes.len() == 0 {
            der_out.extend(&[0x01, 0x00]);
            return der_out;
        }
        if (self.be_bytes[0] & 0x80) == 0x80 { 
            der_out.extend(encode_length_octet(self.be_bytes.len() + 1));
            der_out.push(0x00);
        } else {
            der_out.extend(encode_length_octet(self.be_bytes.len()));
        }
        der_out.extend(&self.be_bytes);
        der_out
    }
}

impl Deserialize for MPUint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer {
            struct MPUintVisitor;
            impl de::Visitor for MPUintVisitor {
                type Value = MPUint;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("big-endian byte buf representing unsigned multi-precision integer")
                }

                fn visit_byte_buf<E>(self, mut v: Vec<u8>) -> Result<Self::Value, E>
                    where E: de::Error {
                        if v.len() > 0 && v[0] == 0 {
                            v = v.split_off(1)
                        }
                        Ok(MPUint{be_bytes: v})
                    }
            }
            deserializer.deserialize_byte_buf(MPUintVisitor)
        }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn mpuint_der_works() {
        assert!(MPUint{be_bytes: vec![]}.to_der() == vec![0x02, 0x01, 0x00]);
        assert!(MPUint{be_bytes: vec![0x01]}.to_der() == vec![0x02, 0x01, 0x01]);
        assert!(MPUint{be_bytes: vec![127]}.to_der() == vec![0x02, 0x01, 0x7f]);
        assert!(MPUint{be_bytes: vec![128]}.to_der() == vec![0x02, 0x02, 0x00, 0x80]);
        assert!(MPUint{be_bytes: vec![1, 0]}.to_der() == vec![0x02, 0x02, 0x01, 0x00]);
    }
}
