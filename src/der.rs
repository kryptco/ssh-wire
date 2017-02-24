use byteorder::{ByteOrder,BigEndian};

pub fn encode_length_octet(len: usize) -> Vec<u8> {
    if len <= 127 { 
            return vec![len as u8];
    }
    let num_len_octets = (len + 255) / 256;
    let mut len_octets = vec![num_len_octets as u8 | 0x80];
    len_octets.extend(&vec![0; num_len_octets]);
    BigEndian::write_uint(&mut len_octets.as_mut_slice().split_first_mut().unwrap().1, len as u64, num_len_octets);
    len_octets
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn encode_len_works() {
        assert!(encode_length_octet(0) == vec![0]);
        assert!(encode_length_octet(1) == vec![1]);
        assert!(encode_length_octet(127) == vec![127]);
        assert!(encode_length_octet(128) == vec![0x81, 128]);
        assert!(encode_length_octet(512) == vec![0x82, 2, 0]);
    }
}
