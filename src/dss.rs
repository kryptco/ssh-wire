use mpint::*;

#[derive(Deserialize, Debug)]
pub struct DSSPublicKey {
    _type: String,
    p: MPUint,
    q: MPUint,
    g: MPUint,
    y: MPUint,
}

#[derive(Deserialize, Debug)]
pub struct DSSSignature {
    _type: String,
    r: [u8; 20],
    s: [u8; 20],
}

#[cfg(test)]
mod test {
    use super::*;
    use super::super::base64;
    use super::super::serde_de;

    #[test]
    fn signature_deserializes() {
        let _ : DSSSignature = serde_de::from_slice(&base64::decode("AAAAB3NzaC1kc3MAAAAoo3+JKSK924b7FHg88V2n338fAsRiCnQLHJLgZUHdvGkc9RnjfVwKOg==").unwrap()).unwrap();
    }

    #[test]
    fn signature_verifies() {
        let pubkey : DSSPublicKey = serde_de::from_slice(&base64::decode("AAAAB3NzaC1kc3MAAACBANGFW2P9xlGU3zWrymJgI/lKo//ZW2WfVtmbsUZJ5uyKArtlQOT2+WRhcg4979aFxgKdcsqAYW3/LS1T2km3jYW/vr4Uzn+dXWODVk5VlUiZ1HFOHf6s6ITcZvjvdbp6ZbpM+DuJT7Bw+h5Fx8Qt8I16oCZYmAPJRtu46o9C2zk1AAAAFQC4gdFGcSbp5Gr0Wd5Ay/jtcldMewAAAIATTgn4sY4Nem/FQE+XJlyUQptPWMem5fwOcWtSXiTKaaN0lkk2p2snz+EJvAGXGq9dTSWHyLJSM2W6ZdQDqWJ1k+cL8CARAqL+UMwF84CR0m3hj+wtVGD/J4G5kW2DBAf4/bqzP4469lT+dF2FRQ2L9JKXrCWcnhMtJUvua8dvnwAAAIB6C4nQfAA7x8oLta6tT+oCk2WQcydNsyugE8vLrHlogoWEicla6cWPk7oXSspbzUcfkjN3Qa6e74PhRkc7JdSdAlFzU3m7LMkXo1MHgkqNX8glxWNVqBSc0YRdbFdTkL0C6gtpklilhvuHQCdbgB3LBAikcRkDp+FCVkUgPC/7Rw==").unwrap()).unwrap();
        let sig : DSSSignature = serde_de::from_slice(&base64::decode("AAAAB3NzaC1kc3MAAAAoo3+JKSK924b7FHg88V2n338fAsRiCnQLHJLgZUHdvGkc9RnjfVwKOg==").unwrap()).unwrap();
        let data = base64::decode("AAAAIOM9VvUIDf3xKQ7XsJsoRVc75coCBdyIRzWx/pri9ivXMg==").unwrap();
    }
}
