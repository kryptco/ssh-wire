use serde::de;
use serde;

use byteorder::{BigEndian, ReadBytesExt};
use std;
use std::fmt;
use std::error;
use std::io::Read;
use std::error::Error as StdError;

const MAX_FIELD_LENGTH : u32 = 1 << 16;

#[derive(Debug)]
pub struct Error {
    pub kind: ErrorKind,
}

#[derive(Debug)]
pub enum ErrorKind {
    UnsupportedType,
    DeserializeUnsupported,
    InvalidLength,
    Io(std::io::Error),
    Utf8(std::str::Utf8Error),
    Custom(String),
}

use self::ErrorKind::*;

impl de::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Error {
        Error{kind: Custom(msg.to_string())}
    }
}

impl error::Error for Error {
     fn description(&self) -> &str {
         match self.kind {
             UnsupportedType => "unsupported type",
             DeserializeUnsupported => "self-decsribing deserialize unsupported",
             InvalidLength => "invalid length",
             Io(ref io_err) => StdError::description(io_err),
             Utf8(ref utf8_err) => StdError::description(utf8_err),
             Custom(ref s) => s,
         }
     }
}

impl From<std::io::Error> for Error {
    fn from(io_err: std::io::Error) -> Self {
        Error{
            kind: Io(io_err),
        }
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(utf8_err: std::str::Utf8Error) -> Self {
        Error{
            kind: Utf8(utf8_err),
        }
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(from_utf8_err: std::string::FromUtf8Error) -> Self {
        Error{
            kind: Utf8(from_utf8_err.utf8_error()),
        }
    }
}

impl fmt::Display for Error {
     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
          write!(f, "{}", self.description())?;
          Ok(())
     }
}

pub fn from_slice<T>(bytes: &[u8]) -> Result<T, Error> 
    where T: serde::Deserialize {
    let mut deserializer = Deserializer{reader: std::io::Cursor::new(bytes.to_vec())};
    serde::Deserialize::deserialize(&mut deserializer)
}   

pub struct Deserializer<R> {
    reader: R,
}

impl<'a, R: Read> de::Deserializer for &'a mut Deserializer<R> {
    type Error = Error;
    fn deserialize<V>(self, _: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            Err(Error{kind: DeserializeUnsupported})
        }
    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            match self.reader.read_u8()? {
                0 => visitor.visit_bool(false),
                _ => visitor.visit_bool(true),
            }
        }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            visitor.visit_u8(self.reader.read_u8()?)
    }

    fn deserialize_u16<V>(self, _: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            Err(Error{kind: UnsupportedType})
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            visitor.visit_u32(self.reader.read_u32::<BigEndian>()?)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            visitor.visit_u64(self.reader.read_u64::<BigEndian>()?)
    }

    fn deserialize_i8<V>(self, _: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            Err(Error{kind: UnsupportedType})
    }

    fn deserialize_i16<V>(self, _: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            Err(Error{kind: UnsupportedType})
    }

    fn deserialize_i32<V>(self, _: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            Err(Error{kind: UnsupportedType})
    }

    fn deserialize_i64<V>(self, _: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            Err(Error{kind: UnsupportedType})
    }

    fn deserialize_f32<V>(self, _: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            Err(Error{kind: UnsupportedType})
    }
    fn deserialize_f64<V>(self, _: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            Err(Error{kind: UnsupportedType})
    }
    
    fn deserialize_char<V>(self, _: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            Err(Error{kind: UnsupportedType})
    }
    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            let len = self.reader.read_u32::<BigEndian>()?;
            if len > MAX_FIELD_LENGTH {
                return Err(Error{kind: InvalidLength});
            }
            let mut buf = vec![0; len as usize];
            self.reader.read_exact(&mut buf)?;
            visitor.visit_str(std::str::from_utf8(&buf)?)
    }
    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            let len = self.reader.read_u32::<BigEndian>()?;
            if len > MAX_FIELD_LENGTH {
                return Err(Error{kind: InvalidLength});
            }
            let mut buf = vec![0; len as usize];
            self.reader.read_exact(&mut buf)?;
            visitor.visit_string(String::from_utf8(buf)?)
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            let len = self.reader.read_u32::<BigEndian>()?;
            let mut buf = vec![0; len as usize];
            if len > MAX_FIELD_LENGTH {
                return Err(Error{kind: InvalidLength});
            }
            self.reader.read_exact(&mut buf)?;
            visitor.visit_bytes(&buf)
    }
    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            let len = self.reader.read_u32::<BigEndian>()?;
            let mut buf = vec![0; len as usize];
            self.reader.read_exact(&mut buf)?;
            visitor.visit_byte_buf(buf)
    }

    fn deserialize_option<V>(self, _: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            Err(Error{kind: UnsupportedType})
    }
    fn deserialize_unit<V>(self, _: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            Err(Error{kind: UnsupportedType})
    }
    fn deserialize_unit_struct<V>(self, _: &'static str, _: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            Err(Error{kind: UnsupportedType})
    }
    fn deserialize_newtype_struct<V>(self, _: &'static str, _: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            Err(Error{kind: UnsupportedType})
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            let len: u32 = serde::de::Deserialize::deserialize(&mut *self)?;
            self.deserialize_seq_fixed_size(len as usize, visitor)
    }

    fn deserialize_seq_fixed_size<V>(self,
                            len: usize,
                            visitor: V) -> Result<V::Value, Self::Error>
        where V: serde::de::Visitor,
    {
        if len > MAX_FIELD_LENGTH as usize {
            return Err(Error{kind: InvalidLength});
        }
        struct SeqVisitor<'a, R: Read + 'a> {
            deserializer: &'a mut Deserializer<R>,
            len: u32,
        }

        impl<'a, 'b: 'a, R: Read + 'b> serde::de::SeqVisitor for SeqVisitor<'a, R> {
            type Error = Error;

            fn visit_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
                where T: serde::de::DeserializeSeed,
            {
                if self.len > 0 {
                    self.len -= 1;
                    let value = try!(serde::de::DeserializeSeed::deserialize(seed, &mut *self.deserializer));
                    Ok(Some(value))
                } else {
                    Ok(None)
                }
            }
        }

        visitor.visit_seq(SeqVisitor { deserializer: self, len: len as u32})
    }
    fn deserialize_tuple<V>(self, _: usize, visitor: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            struct TupleVisitor<'a, R: Read + 'a>(&'a mut Deserializer<R>);

            impl<'a, 'b: 'a, R: Read + 'b> serde::de::SeqVisitor for TupleVisitor<'a, R> {
                type Error = Error;

                fn visit_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
                    where T: serde::de::DeserializeSeed,
                          {
                              let value = try!(serde::de::DeserializeSeed::deserialize(seed, &mut *self.0));
                              Ok(Some(value))
                          }
            }

            visitor.visit_seq(TupleVisitor(self))
    }
    fn deserialize_tuple_struct<V>(self, _: &'static str, len: usize, visitor: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            self.deserialize_tuple(len, visitor)
    }

    fn deserialize_map<V>(self, _: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            Err(Error{kind: UnsupportedType})
    }
    fn deserialize_struct<V>(self, _: &'static str, fields: &'static [&'static str], visitor: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            self.deserialize_tuple(fields.len(), visitor)
    }
    fn deserialize_struct_field<V>(self, _: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            Err(Error{kind: UnsupportedType})
    }
    fn deserialize_enum<V>(self, _enum: &'static str, _: &'static [&'static str], _: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            Err(Error{kind: UnsupportedType})
    }
    fn deserialize_ignored_any<V>(self, _: V) -> Result<V::Value, Self::Error> 
        where V: de::Visitor {
            Err(Error{kind: UnsupportedType})
    }
}


#[cfg(test)]
mod tests {
    extern crate serde;

    use super::Error;
    use super::ErrorKind::*;
    #[test]
    fn ints_deserialize() {
        #[derive(Deserialize, PartialEq, Eq)]
        struct TestInts {
            b: u8,
            i: u32,
            l: u64,
        }
        let wire = b"\xff\x01\x02\x03\x04\x08\x07\x06\x05\x04\x03\x02\x01";
        let deserialized : TestInts = super::from_slice(wire).unwrap();
        assert!(deserialized == TestInts{
            b: 0xff,
            i: 0x01020304,
            l: 0x0807060504030201,
        });
    }

    #[test]
    fn str_deserializes() {
        let wire = b"\x00\x00\x00\x04test";
        let deserialized: String = super::from_slice(wire).unwrap();
        assert!(deserialized == "test");
    }
    #[test]
    fn str_invalid_length_fails() {
        let wire = b"\x00\xff\x00\x04test";
        let deserialized: Result<String, Error> = super::from_slice(wire);
        match deserialized {
            Err(Error{kind: InvalidLength}) => {},
            _ => assert!("expected" == "InvalidLength"),
        }
    }

    #[test]
    fn byte_slice_deserializes() {
        let wire = b"\x00\x00\x00\x10\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
        let deserialized: Vec<u8> = super::from_slice(wire).unwrap();
        assert!(deserialized == b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f");
    }
    #[test]
    fn byte_slice_with_extra_deserializes() {
        let wire = b"\x00\x00\x00\x10\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12";
        let deserialized: Vec<u8> = super::from_slice(wire).unwrap();
        assert!(deserialized == b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f");
    }
    #[test]
    fn byte_slice_too_short_fails() {
        let wire = b"\x00\x00\x00\x10\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e";
        let deserialized: Result<Vec<u8>, Error> = super::from_slice(wire);
        match deserialized {
            Err(Error{kind: Io(_)}) => {},
            _ => assert!("expected" == "IoError"),
        }
    }
    #[test]
    fn byte_slice_invalid_length_fails() {
        let wire = b"\xff\x00\x00\x10\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e";
        let deserialized: Result<Vec<u8>, Error> = super::from_slice(wire);
        match deserialized {
            Err(Error{kind: InvalidLength}) => {},
            _ => assert!("expected" == "InvalidLength"),
        }
    }

    #[test]
    fn tuple_struct_deserializes() {
        #[derive(Deserialize, PartialEq, Eq)]
        struct TestInts(u8, u32, u64);
        let wire = b"\xff\x01\x02\x03\x04\x08\x07\x06\x05\x04\x03\x02\x01";
        let deserialized: TestInts = super::from_slice(wire).unwrap();
        assert!(deserialized == TestInts(0xff, 0x01020304, 0x0807060504030201));
    }

    #[test] 
    fn tuple_deserializes() {
        let wire = b"\xff\x01\x02\x03\x04\x08\x07\x06\x05\x04\x03\x02\x01";
        let deserialized: (u8, u32, u64) = super::from_slice(wire).unwrap();
        assert!(deserialized == (0xff, 0x01020304, 0x0807060504030201));
    }
}
