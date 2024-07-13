//! X.509 certificate support.

// Adapted from yubico-piv-tool:
// <https://github.com/Yubico/yubico-piv-tool/>
//
// Copyright (c) 2014-2016 Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//   * Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//   * Redistributions in binary form must reproduce the above
//     copyright notice, this list of conditions and the following
//     disclaimer in the documentation and/or other materials provided
//     with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use crate::{
    consts::CB_OBJ_MAX,
    error::{Error, Result},
    piv::{sign_data, AlgorithmId, SlotId},
    serialization::*,
    transaction::Transaction,
    yubikey::YubiKey,
    Buffer,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey as CvSigningKey;
use elliptic_curve::sec1::EncodedPoint as EcPublicKey;
use log::error;
use num_bigint_dig::BigUint;
use p256::NistP256;
use p384::NistP384;
use rsa::{PublicKeyParts, RsaPublicKey};
use sha2::{Digest, Sha256, Sha512};
use std::fmt::Display;
use std::{fmt, ops::DerefMut};
use x25519_dalek::PublicKey as CvPublicKey;
use x509::{der::Oid, RelativeDistinguishedName};
use x509_parser::{parse_x509_certificate, x509::SubjectPublicKeyInfo};
use zeroize::Zeroizing;

// TODO: Make these der_parser::oid::Oid constants when it has const fn support.
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_NIST_P256: &str = "1.2.840.10045.3.1.7";
const OID_NIST_P384: &str = "1.3.132.0.34";
const OID_X25519: &str = "1.3.101.110";
const OID_ED25519: &str = "1.3.101.112";

const TAG_CERT: u8 = 0x70;
const TAG_CERT_COMPRESS: u8 = 0x71;
const TAG_CERT_LRC: u8 = 0xFE;

/// A serial number for a [`Certificate`].
#[derive(Clone, Debug)]
pub struct Serial(BigUint);

impl From<BigUint> for Serial {
    fn from(num: BigUint) -> Serial {
        Serial(num)
    }
}

impl From<[u8; 20]> for Serial {
    fn from(bytes: [u8; 20]) -> Serial {
        Serial(BigUint::from_bytes_be(&bytes))
    }
}

impl TryFrom<&[u8]> for Serial {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Serial> {
        if bytes.len() <= 20 {
            Ok(Serial(BigUint::from_bytes_be(bytes)))
        } else {
            Err(Error::ParseError)
        }
    }
}

impl Serial {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes_be()
    }
    /// Returns itself formatted as x509 compatible hex string
    pub fn as_x509_hex(&self) -> String {
        let data = self.to_bytes();
        let raw_hex_string = format!("{:02X?}", data);
        raw_hex_string
            .replace(", ", ":")
            .replace([']', '['], "")
            .to_lowercase()
    }
    /// Returns itself formatted as x509 compatible int string
    pub fn as_x509_int(&self) -> String {
        let Serial(buint) = self;
        format!("{}", buint)
    }
}

impl Display for Serial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_x509_hex())
    }
}

/// Information about how a [`Certificate`] is stored within a YubiKey.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertInfo {
    /// The certificate is uncompressed.
    Uncompressed,

    /// The certificate is gzip-compressed.
    Gzip,
}

impl TryFrom<u8> for CertInfo {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(CertInfo::Uncompressed),
            0x01 => Ok(CertInfo::Gzip),
            _ => Err(Error::InvalidObject),
        }
    }
}

impl From<CertInfo> for u8 {
    fn from(certinfo: CertInfo) -> u8 {
        match certinfo {
            CertInfo::Uncompressed => 0x00,
            CertInfo::Gzip => 0x01,
        }
    }
}

impl x509::AlgorithmIdentifier for AlgorithmId {
    type AlgorithmOid = &'static [u64];

    fn algorithm(&self) -> Self::AlgorithmOid {
        match self {
            // RSA encryption
            AlgorithmId::Rsa1024 | AlgorithmId::Rsa2048 => &[1, 2, 840, 113_549, 1, 1, 1],
            // EC Public Key
            AlgorithmId::EccP256 | AlgorithmId::EccP384 => &[1, 2, 840, 10045, 2, 1],
            // CV Public Key
            AlgorithmId::X25519 => &[1, 3, 101, 110],
            AlgorithmId::Ed25519 => &[1, 3, 101, 112],
        }
    }

    fn parameters<W: std::io::Write>(
        &self,
        w: cookie_factory::WriteContext<W>,
    ) -> cookie_factory::GenResult<W> {
        use x509::der::write::der_oid;

        // From [RFC 5480](https://tools.ietf.org/html/rfc5480#section-2.1.1):
        // ```text
        // ECParameters ::= CHOICE {
        //   namedCurve         OBJECT IDENTIFIER
        //   -- implicitCurve   NULL
        //   -- specifiedCurve  SpecifiedECDomain
        // }
        // ```
        match self {
            AlgorithmId::EccP256 => der_oid(&[1, 2, 840, 10045, 3, 1, 7][..])(w),
            AlgorithmId::EccP384 => der_oid(&[1, 3, 132, 0, 34][..])(w),
            _ => Ok(w),
        }
    }
}

/// Information about a public key within a [`Certificate`].
#[derive(Clone, Eq, PartialEq)]
pub enum PublicKeyInfo {
    /// RSA keys
    Rsa {
        /// RSA algorithm
        algorithm: AlgorithmId,

        /// Public key
        pubkey: RsaPublicKey,
    },

    /// EC P-256 keys
    EcP256(EcPublicKey<NistP256>),

    /// EC P-384 keys
    EcP384(EcPublicKey<NistP384>),

    /// ED25519 Keys
    Ed25519 {
        /// ED25519 Algorithm
        algorithm: AlgorithmId,

        /// Public key
        pubkey: CvSigningKey,
    },

    /// X25519 Keys
    X25519 {
        /// X25519 Algorithm
        algorithm: AlgorithmId,

        /// Public key
        pubkey: CvPublicKey,
    },
}

impl fmt::Debug for PublicKeyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKeyInfo({:?})", self.algorithm())
    }
}

impl PublicKeyInfo {
    fn parse(subject_pki: &SubjectPublicKeyInfo<'_>) -> Result<Self> {
        match subject_pki.algorithm.algorithm.to_string().as_str() {
            OID_RSA_ENCRYPTION => {
                let pubkey = read_pki::rsa_pubkey(&subject_pki.subject_public_key.data)?;

                Ok(PublicKeyInfo::Rsa {
                    algorithm: match pubkey.n().bits() {
                        1024 => AlgorithmId::Rsa1024,
                        2048 => AlgorithmId::Rsa2048,
                        _ => return Err(Error::AlgorithmError),
                    },
                    pubkey,
                })
            }
            OID_EC_PUBLIC_KEY => {
                let key_bytes = &subject_pki.subject_public_key.data;
                let algorithm_parameters = subject_pki
                    .algorithm
                    .parameters
                    .as_ref()
                    .ok_or(Error::InvalidObject)?;

                match read_pki::ec_parameters(algorithm_parameters)? {
                    AlgorithmId::EccP256 => EcPublicKey::<NistP256>::from_bytes(key_bytes)
                        .map(PublicKeyInfo::EcP256)
                        .map_err(|_| Error::InvalidObject),
                    AlgorithmId::EccP384 => EcPublicKey::<NistP384>::from_bytes(key_bytes)
                        .map(PublicKeyInfo::EcP384)
                        .map_err(|_| Error::InvalidObject),
                    _ => Err(Error::AlgorithmError),
                }
            }
            OID_ED25519 => {
                let key_bytes: [u8; 32] = subject_pki
                    .subject_public_key
                    .data
                    .to_vec()
                    .try_into()
                    .unwrap();
                let algorithm_parameters = subject_pki
                    .algorithm
                    .parameters
                    .as_ref()
                    .ok_or(Error::InvalidObject)?;
                match read_pki::cv_parameters(algorithm_parameters)? {
                    AlgorithmId::Ed25519 => Ok(PublicKeyInfo::Ed25519 {
                        algorithm: AlgorithmId::Ed25519,
                        pubkey: CvSigningKey::from(key_bytes),
                    }),
                    _ => Err(Error::AlgorithmError),
                }
            }
            OID_X25519 => {
                let key_bytes: [u8; 32] = subject_pki
                    .subject_public_key
                    .data
                    .to_vec()
                    .try_into()
                    .unwrap();
                let algorithm_parameters = subject_pki
                    .algorithm
                    .parameters
                    .as_ref()
                    .ok_or(Error::InvalidObject)?;
                match read_pki::cv_parameters(algorithm_parameters)? {
                    AlgorithmId::X25519 => Ok(PublicKeyInfo::X25519 {
                        algorithm: AlgorithmId::X25519,
                        pubkey: CvPublicKey::from(key_bytes),
                    }),
                    _ => Err(Error::AlgorithmError),
                }
            }
            _ => Err(Error::InvalidObject),
        }
    }

    /// Returns the algorithm that this public key can be used with.
    pub fn algorithm(&self) -> AlgorithmId {
        match self {
            PublicKeyInfo::Rsa { algorithm, .. } => *algorithm,
            PublicKeyInfo::EcP256(_) => AlgorithmId::EccP256,
            PublicKeyInfo::EcP384(_) => AlgorithmId::EccP384,
            PublicKeyInfo::Ed25519 { algorithm, .. } => *algorithm,
            PublicKeyInfo::X25519 { algorithm, .. } => *algorithm,
        }
    }
}

impl x509::SubjectPublicKeyInfo for PublicKeyInfo {
    type AlgorithmId = AlgorithmId;
    type SubjectPublicKey = Vec<u8>;

    fn algorithm_id(&self) -> AlgorithmId {
        self.algorithm()
    }

    fn public_key(&self) -> Vec<u8> {
        match self {
            PublicKeyInfo::Rsa { pubkey, .. } => {
                cookie_factory::gen_simple(write_pki::rsa_pubkey(pubkey), vec![])
                    .expect("can write to Vec")
            }
            PublicKeyInfo::EcP256(pubkey) => pubkey.as_bytes().to_vec(),
            PublicKeyInfo::EcP384(pubkey) => pubkey.as_bytes().to_vec(),
            PublicKeyInfo::Ed25519 { pubkey, .. } => pubkey.to_bytes().to_vec(),
            PublicKeyInfo::X25519 { pubkey, .. } => pubkey.to_bytes().to_vec(),
        }
    }
}

/// Digest algorithms.
///
/// See RFC 4055 and RFC 8017.
enum DigestId {
    /// Secure Hash Algorithm 256 (SHA256)
    Sha256,
}

impl x509::AlgorithmIdentifier for DigestId {
    type AlgorithmOid = &'static [u64];

    fn algorithm(&self) -> Self::AlgorithmOid {
        match self {
            // See https://tools.ietf.org/html/rfc4055#section-2.1
            DigestId::Sha256 => &[2, 16, 840, 1, 101, 3, 4, 2, 1],
        }
    }

    fn parameters<W: std::io::Write>(
        &self,
        w: cookie_factory::WriteContext<W>,
    ) -> cookie_factory::GenResult<W> {
        // Parameters are an explicit NULL
        // See https://tools.ietf.org/html/rfc8017#appendix-A.2.4
        x509::der::write::der_null()(w)
    }
}

enum SignatureId {
    /// Public-Key Cryptography Standards (PKCS) #1 version 1.5 signature algorithm with
    /// Secure Hash Algorithm 256 (SHA256) and Rivest, Shamir and Adleman (RSA) encryption
    ///
    /// See RFC 4055 and RFC 8017.
    Sha256WithRsaEncryption,

    /// Elliptic Curve Digital Signature Algorithm (DSA) coupled with the Secure Hash
    /// Algorithm 256 (SHA256) algorithm
    ///
    /// See RFC 5758.
    EcdsaWithSha256,

    EdWithSha512,
}

impl x509::AlgorithmIdentifier for SignatureId {
    type AlgorithmOid = &'static [u64];

    fn algorithm(&self) -> Self::AlgorithmOid {
        match self {
            SignatureId::Sha256WithRsaEncryption => &[1, 2, 840, 113_549, 1, 1, 11],
            SignatureId::EcdsaWithSha256 => &[1, 2, 840, 10045, 4, 3, 2],
            SignatureId::EdWithSha512 => &[1, 3, 6, 1, 5, 5, 7, 0, 54],
        }
    }

    fn parameters<W: std::io::Write>(
        &self,
        w: cookie_factory::WriteContext<W>,
    ) -> cookie_factory::GenResult<W> {
        // No parameters for any SignatureId
        Ok(w)
    }
}

/// Certificates
#[derive(Clone, Debug)]
pub struct Certificate {
    serial: Serial,
    #[allow(dead_code)]
    issuer: String,
    subject: String,
    subject_pki: PublicKeyInfo,
    data: Buffer,
}

impl<'a> TryFrom<&'a [u8]> for Certificate {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Self::from_bytes(bytes.to_vec())
    }
}

impl Certificate {
    /// Creates a new self-signed certificate for the given key. Writes the resulting
    /// certificate to the slot before returning it.
    ///
    /// `extensions` is optional; if empty, no extensions will be included. Due to the
    /// need for an `O: Oid` type parameter, users who do not have any extensions should
    /// use the workaround `let extensions: &[x509::Extension<'_, &[u64]>] = &[];`.
    pub fn generate_self_signed<O: Oid>(
        yubikey: &mut YubiKey,
        key: SlotId,
        serial: impl Into<Serial>,
        not_after: Option<DateTime<Utc>>,
        subject: &[RelativeDistinguishedName<'_>],
        subject_pki: PublicKeyInfo,
        extensions: &[x509::Extension<'_, O>],
    ) -> Result<Self> {
        let serial = serial.into();

        let mut tbs_cert = Buffer::new(Vec::with_capacity(CB_OBJ_MAX));

        let signature_algorithm = match subject_pki.algorithm() {
            AlgorithmId::Rsa1024 | AlgorithmId::Rsa2048 => SignatureId::Sha256WithRsaEncryption,
            AlgorithmId::EccP256 | AlgorithmId::EccP384 => SignatureId::EcdsaWithSha256,
            AlgorithmId::Ed25519 => SignatureId::EdWithSha512,
            AlgorithmId::X25519 => return Err(Error::NotSupported),
        };

        cookie_factory::gen(
            x509::write::tbs_certificate(
                &serial.to_bytes(),
                &signature_algorithm,
                // Issuer and subject are the same in self-signed certificates.
                subject,
                Utc::now(),
                not_after,
                subject,
                &subject_pki,
                extensions,
            ),
            tbs_cert.deref_mut(),
        )
        .expect("can serialize to Vec");

        let signature = match signature_algorithm {
            SignatureId::Sha256WithRsaEncryption => {
                use cookie_factory::{combinator::slice, sequence::tuple};
                use x509::{
                    der::write::{der_octet_string, der_sequence},
                    write::algorithm_identifier,
                };

                let em_len = if let AlgorithmId::Rsa1024 = subject_pki.algorithm() {
                    128
                } else {
                    256
                };

                let h = Sha256::digest(&tbs_cert);

                let t = cookie_factory::gen_simple(
                    der_sequence((
                        algorithm_identifier(&DigestId::Sha256),
                        der_octet_string(&h),
                    )),
                    vec![],
                )
                .expect("can serialize into Vec");

                let em = cookie_factory::gen_simple(
                    tuple((
                        slice(&[0x00, 0x01]),
                        slice(&vec![0xff; em_len - t.len() - 3]),
                        slice(&[0x00]),
                        slice(t),
                    )),
                    vec![],
                )
                .expect("can serialize to Vec");

                sign_data(yubikey, &em, subject_pki.algorithm(), key)
            }
            SignatureId::EcdsaWithSha256 => sign_data(
                yubikey,
                &Sha256::digest(&tbs_cert),
                subject_pki.algorithm(),
                key,
            ),
            SignatureId::EdWithSha512 => sign_data(
                yubikey,
                &Sha512::digest(&tbs_cert),
                subject_pki.algorithm(),
                key,
            ),
        }?;

        let mut data = Buffer::new(Vec::with_capacity(CB_OBJ_MAX));

        cookie_factory::gen(
            x509::write::certificate(&tbs_cert, &signature_algorithm, &signature),
            data.deref_mut(),
        )
        .expect("can serialize to Vec");

        let (issuer, subject) = parse_x509_certificate(&data)
            .map(|(_, cert)| {
                (
                    cert.tbs_certificate.issuer.to_string(),
                    cert.tbs_certificate.subject.to_string(),
                )
            })
            .expect("We just serialized this correctly");

        let cert = Certificate {
            serial,
            issuer,
            subject,
            subject_pki,
            data,
        };

        cert.write(yubikey, key, CertInfo::Uncompressed)?;

        Ok(cert)
    }

    /// Read a certificate from the given slot in the YubiKey
    pub fn read(yubikey: &mut YubiKey, slot: SlotId) -> Result<Self> {
        let txn = yubikey.begin_transaction()?;
        let buf = read_certificate(&txn, slot)?;

        if buf.is_empty() {
            return Err(Error::InvalidObject);
        }

        Certificate::from_bytes(buf)
    }

    /// Write this certificate into the YubiKey in the given slot
    pub fn write(&self, yubikey: &mut YubiKey, slot: SlotId, certinfo: CertInfo) -> Result<()> {
        let txn = yubikey.begin_transaction()?;
        write_certificate(&txn, slot, Some(&self.data), certinfo)
    }

    /// Delete a certificate located at the given slot of the given YubiKey
    #[cfg(feature = "untested")]
    #[cfg_attr(docsrs, doc(cfg(feature = "untested")))]
    pub fn delete(yubikey: &mut YubiKey, slot: SlotId) -> Result<()> {
        let txn = yubikey.begin_transaction()?;
        write_certificate(&txn, slot, None, CertInfo::Uncompressed)
    }

    /// Initialize a local certificate struct from the given bytebuffer
    pub fn from_bytes(cert: impl Into<Buffer>) -> Result<Self> {
        let cert = cert.into();

        if cert.is_empty() {
            error!("certificate cannot be empty");
            return Err(Error::SizeError);
        }

        let parsed_cert = match parse_x509_certificate(&cert) {
            Ok((_, cert)) => cert,
            _ => return Err(Error::InvalidObject),
        };

        let serial = Serial::try_from(parsed_cert.tbs_certificate.serial.to_bytes_be().as_slice())
            .map_err(|_| Error::InvalidObject)?;
        let issuer = parsed_cert.tbs_certificate.issuer.to_string();
        let subject = parsed_cert.tbs_certificate.subject.to_string();
        let subject_pki = PublicKeyInfo::parse(&parsed_cert.tbs_certificate.subject_pki)?;

        Ok(Certificate {
            serial,
            issuer,
            subject,
            subject_pki,
            data: cert,
        })
    }

    /// Returns the serial number of the certificate.
    pub fn serial(&self) -> &Serial {
        &self.serial
    }

    /// Returns the Issuer field of the certificate.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns the SubjectName field of the certificate.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the SubjectPublicKeyInfo field of the certificate.
    pub fn subject_pki(&self) -> &PublicKeyInfo {
        &self.subject_pki
    }

    /// Extract the inner buffer
    pub fn into_buffer(self) -> Buffer {
        self.data
    }
}

impl AsRef<[u8]> for Certificate {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

/// Read certificate
pub(crate) fn read_certificate(txn: &Transaction<'_>, slot: SlotId) -> Result<Buffer> {
    let object_id = slot.object_id();

    let buf = match txn.fetch_object(object_id) {
        Ok(b) => b,
        Err(_) => {
            // TODO(tarcieri): is this really ok?
            return Ok(Zeroizing::new(vec![]));
        }
    };

    // TODO(str4d): Check the rest of the buffer (TAG_CERT_COMPRESS and TAG_CERT_LRC)
    if buf[0] == TAG_CERT {
        Tlv::parse_single(buf, TAG_CERT).or_else(|_| {
            // TODO(tarcieri): is this really ok?
            Ok(Zeroizing::new(vec![]))
        })
    } else {
        Ok(buf)
    }
}

/// Write certificate
pub(crate) fn write_certificate(
    txn: &Transaction<'_>,
    slot: SlotId,
    data: Option<&[u8]>,
    certinfo: CertInfo,
) -> Result<()> {
    let object_id = slot.object_id();

    if data.is_none() {
        return txn.save_object(object_id, &[]);
    }

    let data = data.unwrap();

    let mut buf = [0u8; CB_OBJ_MAX];
    let mut offset = Tlv::write(&mut buf, TAG_CERT, data)?;

    // write compression info and LRC trailer
    offset += Tlv::write(&mut buf[offset..], TAG_CERT_COMPRESS, &[certinfo.into()])?;
    offset += Tlv::write(&mut buf[offset..], TAG_CERT_LRC, &[])?;

    txn.save_object(object_id, &buf[..offset])
}

mod read_pki {
    use der_parser::{
        asn1_rs::Any,
        ber::BerObjectContent,
        der::{parse_der_integer, parse_der_sequence_defined_g, DerObject},
        error::BerError,
    };
    use nom::{combinator, sequence::pair, IResult};
    use rsa::{BigUint, RsaPublicKey};

    use super::{OID_ED25519, OID_X25519};
    use super::{OID_NIST_P256, OID_NIST_P384};
    use crate::{piv::AlgorithmId, Error, Result};

    /// From [RFC 8017](https://tools.ietf.org/html/rfc8017#appendix-A.1.1):
    /// ```text
    /// RSAPublicKey ::= SEQUENCE {
    ///     modulus           INTEGER,  -- n
    ///     publicExponent    INTEGER   -- e
    /// }
    /// ```
    pub(super) fn rsa_pubkey(encoded: &[u8]) -> Result<RsaPublicKey> {
        fn parse_rsa_pubkey(i: &[u8]) -> IResult<&[u8], (DerObject<'_>, DerObject<'_>), BerError> {
            parse_der_sequence_defined_g(|i, _| pair(parse_der_integer, parse_der_integer)(i))(i)
        }

        fn rsa_pubkey_parts(i: &[u8]) -> IResult<&[u8], (BigUint, BigUint), BerError> {
            combinator::map(parse_rsa_pubkey, |(modulus, public_exponent)| {
                let n = match modulus.content {
                    BerObjectContent::Integer(s) => BigUint::from_bytes_be(s),
                    _ => panic!("expected DER integer"),
                };
                let e = match public_exponent.content {
                    BerObjectContent::Integer(s) => BigUint::from_bytes_be(s),
                    _ => panic!("expected DER integer"),
                };

                (n, e)
            })(i)
        }

        let (n, e) = match rsa_pubkey_parts(encoded) {
            Ok((_, res)) => res,
            _ => return Err(Error::InvalidObject),
        };

        RsaPublicKey::new(n, e).map_err(|_| Error::InvalidObject)
    }

    /// From [RFC 5480](https://tools.ietf.org/html/rfc5480#section-2.1.1):
    /// ```text
    /// ECParameters ::= CHOICE {
    ///   namedCurve         OBJECT IDENTIFIER
    ///   -- implicitCurve   NULL
    ///   -- specifiedCurve  SpecifiedECDomain
    /// }
    /// ```
    pub(super) fn ec_parameters(parameters: &Any<'_>) -> Result<AlgorithmId> {
        let curve_oid = parameters.as_oid().map_err(|_| Error::InvalidObject)?;

        match curve_oid.to_string().as_str() {
            OID_NIST_P256 => Ok(AlgorithmId::EccP256),
            OID_NIST_P384 => Ok(AlgorithmId::EccP384),
            _ => Err(Error::AlgorithmError),
        }
    }

    pub(super) fn cv_parameters(parameters: &Any<'_>) -> Result<AlgorithmId> {
        let curve_oid = parameters.as_oid().map_err(|_| Error::InvalidObject)?;

        match curve_oid.to_string().as_str() {
            OID_ED25519 => Ok(AlgorithmId::Ed25519),
            OID_X25519 => Ok(AlgorithmId::X25519),
            _ => Err(Error::AlgorithmError),
        }
    }
}

mod write_pki {
    use cookie_factory::{SerializeFn, WriteContext};
    use rsa::{BigUint, PublicKeyParts, RsaPublicKey};
    use std::io::Write;
    use x509::der::write::{der_integer, der_sequence};

    /// Encodes a usize as an ASN.1 integer using DER.
    fn der_integer_biguint<'a, W: Write + 'a>(num: &'a BigUint) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| der_integer(&num.to_bytes_be())(w)
    }

    /// From [RFC 8017](https://tools.ietf.org/html/rfc8017#appendix-A.1.1):
    /// ```text
    /// RSAPublicKey ::= SEQUENCE {
    ///     modulus           INTEGER,  -- n
    ///     publicExponent    INTEGER   -- e
    /// }
    /// ```
    pub(super) fn rsa_pubkey<'a, W: Write + 'a>(
        pubkey: &'a RsaPublicKey,
    ) -> impl SerializeFn<W> + 'a {
        der_sequence((
            der_integer_biguint(pubkey.n()),
            der_integer_biguint(pubkey.e()),
        ))
    }
}
