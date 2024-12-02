//! This crate provides functions to work with DAPS certificates.

#![deny(unsafe_code, rust_2018_idioms, clippy::unwrap_used)]
#![warn(rust_2024_compatibility, clippy::pedantic)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::type_complexity
)]

mod internal;

/**
 * Encapsulates the components of an RSA key (exponent and modulus).
 */
#[derive(Clone, Debug)]
pub struct RSAKeyParameters<'a> {
    pub exponent: std::borrow::Cow<'a, [u8]>,
    pub modulus: std::borrow::Cow<'a, [u8]>,
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/**
 * The `CertUtil` provides methods for extracting different information from an .p12 file, issued by
 * the DAPS. It is optimised for reading the certificate file only once and then jut extracting the
 * requested details from that loaded file.
 */
pub struct CertUtil {
    /// The loaded and parsed .p12 file
    parsed_pkcs12: openssl::pkcs12::ParsedPkcs12_2,
}

impl CertUtil {
    /**
     * Basically the constructor for the util. Loads and parses the .p12 file and then crates the
     * `CertUtil` out of it.
     */
    pub fn load_certificate(path: &std::path::Path, password: &str) -> Result<Self> {
        let parsed_pkcs12 = internal::read_and_parse_p12(path, password)?;
        Ok(Self { parsed_pkcs12 })
    }

    /**
     * Extracts the *Subject Key Identifier* and *Authority Key Identifier* from a certificate and creates
     * a String of the form "`SKI:keyid:AKI`", where SKI and AKI are the hex-encoded values of the
     * Subject Key Identifier* and *Authority Key Identifier*, respectively.
     */
    pub fn ski_aki<'a>(
        &self,
    ) -> Result<std::borrow::Cow<'a, str>> {
        Ok(internal::ski_aki(
            &self
                .parsed_pkcs12
                .cert
                .clone()
                .ok_or("Certificate not found in .p12 file")?,
        ))
    }

    /**
     * Extracts the private key as a DER-encoded key type format.
     */
    pub fn private_key_der<'a>(
        &self,
    ) -> Result<std::borrow::Cow<'a, [u8]>> {
        let private_key_der = self
            .parsed_pkcs12
            .pkey
            .clone()
            .ok_or("Private key not found in .p12 file")?
            .private_key_to_der()?;

        Ok(std::borrow::Cow::from(private_key_der))
    }

    /**
     * Extracts the RSA Exponent and Modulus from the certificate.
     */
    pub fn rsa_exponent_and_modulus<'a>(&self) -> Result<RSAKeyParameters<'a>>
    {
        let (exponent, modulus) = internal::rsa_exponent_and_modulus(
            &self
                .parsed_pkcs12
                .cert
                .clone()
                .ok_or("Certificate not found in .p12 file")?,
        )?;

        Ok(RSAKeyParameters { exponent, modulus })
    }

    /**
     * Calculates an SSH-Fingerprint of the Public Key
     */
    #[cfg(feature = "fingerprint")]
    pub fn fingerprint<'a>(&self) -> Result<String> {
        let rsa_components = self.rsa_exponent_and_modulus()?;
        let public_key = openssh_keys::PublicKey::from_rsa(rsa_components.exponent.to_vec(), rsa_components.modulus.to_vec());
        Ok(public_key.fingerprint())
    }

    #[cfg(feature = "biscuit")]
    pub fn to_biscuit_rsa_key_parameters(&self) -> Result<biscuit::jwk::RSAKeyParameters> {
        let rsa_key_parameters = self.rsa_exponent_and_modulus()?;

        Ok(biscuit::jwk::RSAKeyParameters {
            key_type: biscuit::jwk::RSAKeyType::RSA,
            e: num_bigint::BigUint::from_bytes_be(rsa_key_parameters.exponent.as_ref()),
            n: num_bigint::BigUint::from_bytes_be(rsa_key_parameters.modulus.as_ref()),
            ..Default::default()
        })
    }
}


#[cfg(test)]
mod test {
    use super::*;

    /// Loads a certificate and extracts the SKI:AKI
    #[test]
    fn test_ski_aki() {
        let util = CertUtil::load_certificate(
            std::path::Path::new("./testdata/connector-certificate.p12"),
            "Password1",
        )
        .expect("Setting up CertUtil failed");

        let ski_aki = util.ski_aki().expect("Failed extracting SKI:AKI");

        assert_eq!(ski_aki, "65:55:CE:32:79:B4:1A:BD:23:91:D1:27:4A:CE:05:BC:0A:D9:92:E5:keyid:65:55:CE:32:79:B4:1A:BD:23:91:D1:27:4A:CE:05:BC:0A:D9:92:E5");
    }

    #[test]
    fn test_private_key_der() {
        let util = CertUtil::load_certificate(
            std::path::Path::new("./testdata/connector-certificate.p12"),
            "Password1",
        )
        .expect("Setting up CertUtil failed");

        let private_key_der = util
            .private_key_der()
            .expect("Failed extracting private key");
        assert_eq!(
            private_key_der,
            vec![
                48, 130, 4, 164, 2, 1, 0, 2, 130, 1, 1, 0, 172, 9, 10, 208, 55, 242, 162, 35, 109,
                22, 3, 184, 10, 73, 31, 16, 133, 55, 154, 79, 32, 202, 59, 102, 232, 228, 44, 103,
                46, 14, 196, 213, 186, 134, 198, 227, 238, 74, 251, 163, 137, 208, 122, 86, 154,
                85, 104, 145, 111, 38, 63, 65, 157, 143, 120, 225, 134, 222, 14, 224, 31, 196, 115,
                173, 112, 171, 98, 233, 250, 204, 33, 38, 245, 82, 84, 211, 140, 199, 173, 178, 51,
                170, 39, 228, 182, 32, 158, 237, 245, 233, 121, 202, 229, 79, 122, 192, 95, 69, 32,
                18, 124, 237, 164, 239, 93, 200, 226, 127, 22, 53, 96, 121, 152, 30, 179, 165, 78,
                214, 96, 99, 12, 167, 130, 213, 51, 57, 81, 211, 7, 157, 186, 93, 33, 68, 62, 231,
                96, 146, 74, 215, 203, 188, 117, 32, 46, 112, 70, 75, 87, 141, 111, 99, 47, 175, 9,
                57, 215, 228, 229, 144, 231, 165, 145, 234, 90, 193, 141, 200, 17, 32, 37, 92, 194,
                27, 198, 142, 12, 65, 206, 170, 254, 121, 148, 253, 40, 249, 147, 86, 255, 74, 181,
                223, 125, 233, 237, 13, 111, 248, 220, 215, 214, 22, 104, 196, 55, 61, 163, 224, 5,
                58, 192, 117, 148, 210, 222, 190, 114, 92, 6, 111, 166, 165, 40, 230, 127, 11, 100,
                63, 139, 62, 17, 202, 174, 205, 59, 131, 25, 60, 107, 81, 132, 23, 126, 20, 148,
                35, 146, 69, 136, 191, 254, 126, 99, 180, 23, 245, 2, 3, 1, 0, 1, 2, 130, 1, 0, 34,
                162, 60, 98, 208, 76, 160, 207, 44, 124, 40, 218, 1, 122, 24, 142, 169, 31, 25, 73,
                242, 82, 60, 84, 186, 176, 138, 238, 231, 195, 17, 229, 236, 68, 11, 96, 226, 61,
                134, 188, 244, 246, 251, 86, 25, 130, 117, 199, 135, 158, 165, 207, 246, 34, 38,
                230, 18, 82, 124, 160, 170, 204, 144, 52, 59, 209, 73, 27, 205, 65, 144, 176, 8,
                229, 223, 13, 106, 211, 93, 56, 217, 181, 89, 12, 46, 141, 81, 41, 155, 94, 250,
                69, 186, 85, 254, 162, 161, 91, 103, 122, 73, 91, 199, 95, 104, 28, 83, 218, 221,
                115, 247, 252, 234, 190, 205, 144, 75, 87, 149, 182, 131, 26, 235, 24, 52, 84, 135,
                15, 245, 136, 83, 131, 102, 217, 149, 105, 73, 186, 191, 84, 12, 195, 165, 152,
                160, 141, 120, 31, 83, 91, 200, 56, 32, 87, 247, 206, 66, 121, 89, 246, 131, 104,
                208, 120, 183, 41, 128, 82, 143, 168, 140, 158, 236, 109, 70, 167, 63, 139, 225,
                113, 216, 181, 87, 117, 86, 49, 83, 34, 206, 18, 141, 147, 118, 43, 86, 81, 99, 3,
                236, 53, 157, 149, 160, 70, 216, 227, 30, 117, 195, 223, 73, 23, 180, 146, 106, 17,
                66, 86, 198, 108, 10, 161, 220, 106, 65, 5, 72, 165, 209, 120, 105, 91, 142, 73,
                141, 215, 33, 197, 104, 16, 229, 60, 92, 183, 94, 178, 141, 78, 196, 74, 120, 2,
                100, 1, 127, 185, 2, 129, 129, 0, 239, 61, 151, 253, 224, 20, 173, 82, 89, 71, 109,
                132, 79, 252, 130, 226, 206, 32, 53, 25, 80, 7, 251, 15, 187, 185, 224, 170, 162,
                49, 21, 134, 72, 51, 234, 30, 235, 229, 154, 68, 3, 21, 78, 200, 149, 78, 63, 76,
                251, 204, 186, 115, 157, 144, 128, 158, 97, 87, 83, 221, 8, 172, 41, 116, 245, 44,
                170, 195, 36, 212, 129, 103, 86, 225, 203, 66, 199, 118, 71, 57, 124, 75, 116, 20,
                147, 247, 82, 132, 20, 87, 67, 8, 198, 201, 147, 120, 235, 121, 106, 145, 236, 143,
                55, 34, 96, 109, 242, 77, 219, 125, 22, 242, 23, 55, 159, 197, 62, 77, 143, 49,
                220, 1, 42, 126, 254, 226, 18, 157, 2, 129, 129, 0, 184, 22, 58, 20, 10, 131, 79,
                246, 152, 41, 12, 115, 86, 48, 243, 232, 111, 167, 102, 239, 221, 118, 131, 50, 6,
                102, 162, 125, 53, 60, 12, 79, 107, 73, 111, 97, 38, 90, 238, 49, 125, 117, 50, 36,
                135, 75, 143, 78, 85, 7, 196, 75, 151, 249, 15, 70, 1, 2, 179, 9, 246, 231, 71, 58,
                170, 173, 228, 84, 193, 74, 150, 48, 253, 87, 47, 67, 45, 179, 186, 154, 75, 118,
                244, 188, 52, 93, 160, 227, 146, 244, 91, 148, 75, 205, 216, 106, 67, 189, 123,
                201, 234, 194, 26, 249, 126, 230, 243, 61, 34, 216, 29, 137, 219, 226, 108, 250, 1,
                194, 71, 104, 146, 61, 180, 69, 122, 69, 207, 57, 2, 129, 129, 0, 218, 213, 161,
                112, 245, 6, 148, 223, 205, 144, 123, 137, 218, 204, 100, 64, 232, 65, 39, 176,
                230, 182, 214, 28, 183, 31, 184, 116, 252, 117, 31, 118, 60, 23, 88, 161, 62, 48,
                64, 98, 211, 219, 42, 188, 105, 110, 48, 146, 207, 132, 158, 76, 97, 37, 43, 177,
                51, 226, 248, 112, 39, 157, 171, 50, 51, 141, 207, 9, 63, 104, 46, 146, 3, 51, 248,
                132, 54, 5, 103, 243, 26, 81, 190, 117, 144, 63, 91, 184, 59, 14, 242, 223, 85, 78,
                79, 89, 253, 50, 139, 155, 189, 33, 231, 81, 199, 152, 234, 89, 243, 90, 65, 161,
                226, 64, 220, 33, 68, 243, 22, 247, 137, 129, 123, 136, 188, 198, 184, 53, 2, 129,
                129, 0, 132, 152, 206, 0, 189, 137, 212, 65, 69, 92, 219, 240, 255, 246, 134, 217,
                184, 3, 22, 172, 84, 19, 23, 113, 35, 23, 46, 151, 141, 142, 209, 55, 43, 138, 91,
                197, 216, 128, 202, 237, 174, 246, 137, 197, 178, 6, 133, 20, 225, 62, 148, 239,
                246, 105, 153, 204, 204, 209, 138, 240, 244, 125, 166, 218, 229, 50, 24, 51, 204,
                126, 211, 44, 58, 111, 96, 69, 189, 87, 166, 99, 153, 83, 247, 248, 208, 167, 88,
                74, 84, 1, 219, 45, 56, 100, 239, 43, 171, 219, 130, 156, 240, 146, 28, 39, 246,
                118, 152, 98, 67, 4, 244, 81, 230, 166, 115, 228, 168, 251, 173, 191, 239, 6, 175,
                33, 20, 111, 208, 81, 2, 129, 128, 106, 250, 211, 58, 51, 149, 167, 48, 43, 73, 70,
                204, 181, 97, 162, 161, 42, 100, 18, 172, 12, 241, 231, 147, 180, 106, 196, 123,
                106, 158, 117, 255, 34, 74, 199, 198, 54, 228, 163, 142, 99, 134, 241, 97, 202, 43,
                54, 17, 63, 48, 205, 157, 80, 34, 108, 210, 129, 74, 151, 53, 246, 32, 224, 226,
                193, 217, 86, 104, 110, 169, 32, 224, 142, 54, 233, 154, 213, 31, 157, 207, 209,
                10, 139, 84, 27, 48, 194, 143, 186, 93, 128, 61, 120, 9, 178, 6, 198, 141, 185,
                185, 62, 23, 146, 234, 146, 88, 65, 126, 70, 211, 103, 179, 173, 143, 83, 140, 140,
                205, 74, 125, 243, 40, 9, 253, 85, 17, 189, 53
            ]
        );
    }

    #[test]
    fn test_rsa_exponents_and_modulus() {
        let util = CertUtil::load_certificate(
            std::path::Path::new("./testdata/connector-certificate.p12"),
            "Password1",
        )
        .expect("Setting up CertUtil failed");

        let RSAKeyParameters {exponent, modulus} = util
            .rsa_exponent_and_modulus()
            .expect("Failed extracting RSA modulus");
        assert_eq!(exponent, vec![1, 0, 1]);
        assert_eq!(
            modulus,
            vec![
                172, 9, 10, 208, 55, 242, 162, 35, 109, 22, 3, 184, 10, 73, 31, 16, 133, 55, 154,
                79, 32, 202, 59, 102, 232, 228, 44, 103, 46, 14, 196, 213, 186, 134, 198, 227, 238,
                74, 251, 163, 137, 208, 122, 86, 154, 85, 104, 145, 111, 38, 63, 65, 157, 143, 120,
                225, 134, 222, 14, 224, 31, 196, 115, 173, 112, 171, 98, 233, 250, 204, 33, 38,
                245, 82, 84, 211, 140, 199, 173, 178, 51, 170, 39, 228, 182, 32, 158, 237, 245,
                233, 121, 202, 229, 79, 122, 192, 95, 69, 32, 18, 124, 237, 164, 239, 93, 200, 226,
                127, 22, 53, 96, 121, 152, 30, 179, 165, 78, 214, 96, 99, 12, 167, 130, 213, 51,
                57, 81, 211, 7, 157, 186, 93, 33, 68, 62, 231, 96, 146, 74, 215, 203, 188, 117, 32,
                46, 112, 70, 75, 87, 141, 111, 99, 47, 175, 9, 57, 215, 228, 229, 144, 231, 165,
                145, 234, 90, 193, 141, 200, 17, 32, 37, 92, 194, 27, 198, 142, 12, 65, 206, 170,
                254, 121, 148, 253, 40, 249, 147, 86, 255, 74, 181, 223, 125, 233, 237, 13, 111,
                248, 220, 215, 214, 22, 104, 196, 55, 61, 163, 224, 5, 58, 192, 117, 148, 210, 222,
                190, 114, 92, 6, 111, 166, 165, 40, 230, 127, 11, 100, 63, 139, 62, 17, 202, 174,
                205, 59, 131, 25, 60, 107, 81, 132, 23, 126, 20, 148, 35, 146, 69, 136, 191, 254,
                126, 99, 180, 23, 245
            ]
        );
    }

    #[test]
    #[cfg(feature = "fingerprint")]
    fn test_fingerprint() {
        let util = CertUtil::load_certificate(
            std::path::Path::new("./testdata/connector-certificate.p12"),
            "Password1",
        )
            .expect("Setting up CertUtil failed");

        let fingerprint: String = util
            .fingerprint()
            .expect("Failed calculating fingerprint");
        assert_eq!(fingerprint, "iOR/+C3TMSfMk1SMjzk4X6cT2KUt+4Vv/2MCdBj/I3w".to_string());
    }
}
