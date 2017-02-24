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

