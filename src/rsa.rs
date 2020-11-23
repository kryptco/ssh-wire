use mpint::*;

#[derive(Deserialize, Debug)]
pub struct RSAPublicKey {
    _type: String,
    public_exponent: MPUint,
    modulus: MPUint,
}

impl RSAPublicKey {
    pub fn verify(&self, signature: &RSASignature, message: &[u8]) -> bool {
        use ring::signature;

        let params = match signature._type.as_ref() {
            "ssh-rsa" => {
                &ring::signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY
            },
            "rsa-sha2-256" => {
                &ring::signature::RSA_PKCS1_2048_8192_SHA256
            },
            "rsa-sha2-512" => {
                &ring::signature::RSA_PKCS1_2048_8192_SHA512
            },
            _ => {
                return false;
            },
        };

        let public_key = ring::signature::RsaPublicKeyComponents {
            n: self.modulus.as_ref(),
            e: self.public_exponent.as_ref()
        };

        public_key.verify(params, message, signature.signature.padded_to_at_least(self.modulus.as_ref().len()).as_ref()).is_ok()
    }
}

#[derive(Deserialize, Debug)]
pub struct RSASignature {
    _type: String,
    signature: MPUint,
}

#[cfg(test)]
mod test {
    struct RSATestCase {
        pk: String,
        sig: String,
        data: String,
    }
    use super::super::base64;
    use super::super::serde_de;
    use super::*;
    #[test]
    fn test_sig_modulus_same_size() {
        let rsa_test_case = RSATestCase{
            pk: "AAAAB3NzaC1yc2EAAAADAQABAAABAQCy+nQ5jr9m4Mil8Llh6nqdN8uX25eljQfaoFdl8K1ufNt26BulxMn41prse+k5cDueL6w06xglVtx1FU4S8uhkbB2WZo05shnUvoNXU6hfQR0nT0Esfk8PqjOl69JVnV8NmVGtSmnMVgJNlvXdQrvvWcDYyI8RLR5bvVFrvMhjSOk8Vb81eJ5TqgJ/Ae+UsG1+uSjySORIuuv7vFsQNB93RE8d68LjQ6QDZB8j02UFNlwsGb+SKEufAlkOgGHTDS3P6lxZLc0AW5691vL58D253CpzNBcnu5llbrdfr/XKoOCQusMOclBN69LrbPWvTx6Tvs3CBwH7XY6WuATId+Wr".into(),
            sig: "AAAAB3NzaC1yc2EAAAEADQc5AG5LwQyee6txeY+XvrQ8/+ihJ84vz4nK4Jtpv3r6efPvq20UgAbTzhx/03RGdo+nZtRumCWDFHrW45unEdcSHuzlrm9v9UVwpKseQO89SnDpA2Tt6UBlJZuVixkldlhFlmrun+GeAxYHxVLeSEL7oaZ/TicQnQFMCvcfD82YMUXxk81SIssEtUVyZOq9Qi2h37xwNz+sSYO37Hkof6nYuJ529DgxcRiJEzIRN03oNoglRi8IZz8LHBLxu3dr/jikxXkZ1/YFt/FMGjhDlp3Yxqj2CPxJ+uyfaCJgbLcgv8tfhSiE8DxOK/WMyP6bLxnC04AOcsrY7Cn9BdvMpw==".into(),
            data: "px7rRWZKhARrnNXbjNv/IRmdXE2dnivE+AVhWDb26FQ=".into(),
        };
        test_rsa_case(&rsa_test_case, "ssh-rsa");
    }

    #[test]
    fn test_sig_smaller_than_modulus() {
        let test_case = RSATestCase{
            pk: "AAAAB3NzaC1yc2EAAAADAQABAAABAQCy+nQ5jr9m4Mil8Llh6nqdN8uX25eljQfaoFdl8K1ufNt26BulxMn41prse+k5cDueL6w06xglVtx1FU4S8uhkbB2WZo05shnUvoNXU6hfQR0nT0Esfk8PqjOl69JVnV8NmVGtSmnMVgJNlvXdQrvvWcDYyI8RLR5bvVFrvMhjSOk8Vb81eJ5TqgJ/Ae+UsG1+uSjySORIuuv7vFsQNB93RE8d68LjQ6QDZB8j02UFNlwsGb+SKEufAlkOgGHTDS3P6lxZLc0AW5691vL58D253CpzNBcnu5llbrdfr/XKoOCQusMOclBN69LrbPWvTx6Tvs3CBwH7XY6WuATId+Wr".into(),
            sig: "AAAAB3NzaC1yc2EAAAEAAGFtFeQVT+Js31n+S3YuAs3Hx08CKv8XAREoqm+uq40j8qPQG/fRCqB3lT+PkwDdLibqIbLCHKAThJq9ft+hZxa/xv3LegxjJvNhXHR8pk2BxnZXQvs6RmJjFHUJHY8/bylA+zSYssOYdeq6PJogTudJ9NenlksmFPmQ4VkCdp3JPo2Y+JEuT7CcSNYL4zrQMXXLTfZV0/SZ0E3Z+ZBJttQI8c68WNd++rPt7tFkvmbb/k7TtSt2pwIZqHX15WKkm/41An/WqXcUwk2VMdUf36SG5X2qPzCC9yPAqphhSKitFOXQaP3nEWGocbSb6vpBACb+MRbjdFGkdCJDfAzQvQ==".into(),
            data: "TnIe9958AKl/iBf9PuMUTSRtPlUUBADl05przXuu83k=".into(),
        };
        test_rsa_case(&test_case, "ssh-rsa");
    }

    #[test]
    fn test_sha256() {
        let test_case = RSATestCase{
            pk: "AAAAB3NzaC1yc2EAAAADAQABAAABAQDLRh4J3T/qF2/lj64/arA3OTw411KRgtOfO9D5psqyZLTPuFzd8KIEKdNdAQBejEHrIT1EgC0JJ9Ti5Ae9cg86sYZ1oMVbfFuYyS4RhznDnMdnZ+0aetkkS/G2gPZXknFeM96Dj6DktmuZT1B7aN5BoKE/Zi4sSbFaBjUYYK3VoqRe3j3uQJyAe7oa4IUA8N9rpZUF8O6AOLlI8gt+rG2l1Y2GaBLJKm3dKMHi6v9xada6j9m/yypK63F0C0QTdw88J0IxjwA3ZnUDFJGcSLg0lEiYcKPp9CZT4jLIF+J0SgY5RNLMg6fTws27RnOgKJcPeX0mltIFvlVM45ZnmbOZ".into(),
            sig: "AAAADHJzYS1zaGEyLTI1NgAAAQDGsWJlKLzhFl+5Fab2XyfvsLeQZvTsSIMNJAiXqhlnX+oL41GPwH5tRsZ1PftI8QQRgqF1+rgueLtSklnEko6WzNSUoB/tQ88lUwV3M/vcr7FTgRzixA7Z7HfBvoLg/hDlHQQgZRZwyU4bwEiscJ3qjZMK3Y5rnquW6u+sLyfl0UDnZB0UhuxJB5CDVqG/icZqDzZevxp0yVS8QTxYBurncVk9rb3Savn4SnJmPE5O4DQTELB4NijuyZEQWWi8o2e+MoIzmcjDQQW2Dq6IIiL1cH+NKKRAvJ8WiGosndgbV0DobJF8+wv9n9OuzvibXr9qKy8QF3CXBCfhqiMXYn5F".into(),
            data: "3v69kWrCoPV+Al/rhTiyLtedwfPNgwx+gkRhXqna4iE=".into(),
        };
        test_rsa_case(&test_case, "rsa-sha2-256");
    }

    #[test]
    fn test_sha512() {
        let test_case = RSATestCase{
            pk: "AAAAB3NzaC1yc2EAAAADAQABAAABAQDLRh4J3T/qF2/lj64/arA3OTw411KRgtOfO9D5psqyZLTPuFzd8KIEKdNdAQBejEHrIT1EgC0JJ9Ti5Ae9cg86sYZ1oMVbfFuYyS4RhznDnMdnZ+0aetkkS/G2gPZXknFeM96Dj6DktmuZT1B7aN5BoKE/Zi4sSbFaBjUYYK3VoqRe3j3uQJyAe7oa4IUA8N9rpZUF8O6AOLlI8gt+rG2l1Y2GaBLJKm3dKMHi6v9xada6j9m/yypK63F0C0QTdw88J0IxjwA3ZnUDFJGcSLg0lEiYcKPp9CZT4jLIF+J0SgY5RNLMg6fTws27RnOgKJcPeX0mltIFvlVM45ZnmbOZ".into(),
            sig: "AAAADHJzYS1zaGEyLTUxMgAAAQACbYsC8PVz87qPk10lx7rlxk9iQupOPwECGQNm9HLkwDby08zaucRy+5hILJJRsZhGvUV2aeFXn8u43J2XR3vzJa+Q03yIoWLI71C/Fd9DQ48+wP4GozZJSoJ/G5eKSh3I68ICieL56utTvnDQMJQEzkDtDdis1RctqPJzYNaDBdukOkhlNwhI47XFVmOwRT4/agWFgyJR0uSw60dybubjMPYGqyrPJ9dIkGh1dBBWLLyIgKAl++iviNna3LFsBpiQXCKAOOStOY9n/28+V9zbw4OY/EcKUee3otTBMQ+zbYOvjrTs6ZFPl6VtjejozPMyfpU+DI5xlerf23gnTfdc".into(),
            data: "k5LHJiiWxnx0NabgxMF+u1poOCQUd5IZPRJqRfMH+4Y=".into(),
        };
        test_rsa_case(&test_case, "rsa-sha2-512");
    }

    fn test_rsa_case(rsa_test_case: &RSATestCase, expected_sig_type: &str) {
        let rsa_public_key : RSAPublicKey = serde_de::from_slice(
            &base64::decode(&rsa_test_case.pk).unwrap()
            ).unwrap();
        assert!(rsa_public_key._type == "ssh-rsa");
        let rsa_signature: RSASignature = serde_de::from_slice(
            &base64::decode(&rsa_test_case.sig).unwrap()
            ).unwrap();
        assert!(rsa_signature._type == expected_sig_type);
        assert!(rsa_signature.signature.padded_to_at_least(rsa_public_key.modulus.as_ref().len()).len()  == rsa_public_key.modulus.as_ref().len());

        let message_bytes = base64::decode(&rsa_test_case.data).unwrap();

        assert!(rsa_public_key.verify(&rsa_signature, &message_bytes));
    }
    
}
