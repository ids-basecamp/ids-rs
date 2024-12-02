/// Reads a .p12 file and parses it into an internal representation of the *OpenSSL Library*.
pub(super) fn read_and_parse_p12(
    p12_file_path: &std::path::Path,
    password: &str,
) -> super::Result<openssl::pkcs12::ParsedPkcs12_2> {
    // Read the .p12 file
    let buf = std::fs::read(p12_file_path)?;

    // Parse the contents of the .p12 file
    let pkcs12 = openssl::pkcs12::Pkcs12::from_der(buf.as_slice())?;
    pkcs12.parse2(password).map_err(Into::into)
}

/**
 * Extracts the *Subject Key Identifier* and *Authority Key Identifier* from a certificate and creates
 * a String of the form "`SKI:keyid:AKI`", where SKI and AKI are the hex-encoded values of the
 * Subject Key Identifier* and *Authority Key Identifier*, respectively.
 */
pub(super) fn ski_aki<'a>(
    x509: &openssl::x509::X509,
) -> std::borrow::Cow<'a, str> {
    let ski = x509
        .subject_key_id()
        .expect("SKI is required to exist in Certificate")
        .as_slice()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<String>>()
        .join(":");

    let aki = x509
        .authority_key_id()
        .expect("AKI is required to exist in Certificate")
        .as_slice()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<String>>()
        .join(":");

    std::borrow::Cow::from([ski, aki].join(":keyid:"))
}

/// Extracts the RSA components of a x509 Certificate
pub(super) fn rsa_exponent_and_modulus<'a>(
    x509: &openssl::x509::X509,
) -> super::Result<(std::borrow::Cow<'a, [u8]>, std::borrow::Cow<'a, [u8]>)>
{
    // Get public key from x509 certificate
    let public_key = x509
        .public_key()
        .expect("x509 certificate contains no public key");

    // Check type of key to be RSA, otherwise this function cannot help
    if public_key.id() != openssl::pkey::Id::RSA {
        return Err("x509 Certificate does not contain a RSA key".into());
    }

    // Extract Exponent (e) and Modulus (n)
    if let Ok(rsa) = public_key.rsa() {
        Ok((
            std::borrow::Cow::from(rsa.e().to_vec()),
            std::borrow::Cow::from(rsa.n().to_vec()),
        ))
    } else {
        Err("".into())
    }
}