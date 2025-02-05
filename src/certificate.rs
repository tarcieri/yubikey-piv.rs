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
    piv::SlotId,
    serialization::*,
    transaction::Transaction,
    yubikey::YubiKey,
    Buffer,
};
use log::error;
use x509_cert::{
    builder::{profile::BuilderProfile, Builder, CertificateBuilder},
    der::{referenced::OwnedToRef, Decode, Encode},
    name::Name,
    serial_number::SerialNumber,
    spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef},
    time::Validity,
};
use zeroize::Zeroizing;

const TAG_CERT: u8 = 0x70;
const TAG_CERT_COMPRESS: u8 = 0x71;
const TAG_CERT_LRC: u8 = 0xFE;

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

/// Certificates
#[derive(Clone, Debug)]
pub struct Certificate {
    /// Inner certificate
    pub cert: x509_cert::Certificate,
}

impl Certificate {
    /// Creates a new self-signed certificate for the given key. Writes the resulting
    /// certificate to the slot before returning it.
    ///
    /// `extensions` is optional; if empty, no extensions will be included. Due to the
    /// need for an `O: Oid` type parameter, users who do not have any extensions should
    /// use the workaround `let extensions: &[x509_cert::Extension<'_, &[u64]>] = &[];`.
    pub fn generate_self_signed<F, KT: yubikey_signer::KeyType>(
        yubikey: &mut YubiKey,
        key: SlotId,
        serial: SerialNumber,
        validity: Validity,
        subject: Name,
        subject_pki: SubjectPublicKeyInfoOwned,
        extensions: F,
    ) -> Result<Self>
    where
        F: FnOnce(&mut CertificateBuilder<SelfSigned>) -> der::Result<()>,
    {
        let signer =
            yubikey_signer::Signer::<'_, KT>::new(yubikey, key, subject_pki.owned_to_ref())?;
        let mut builder =
            CertificateBuilder::new(SelfSigned { subject }, serial, validity, subject_pki)
                .map_err(|_| Error::KeyError)?;

        // Add custom extensions
        extensions(&mut builder)?;

        let cert = builder.build(&signer).map_err(|_| Error::KeyError)?;
        let cert = Self { cert };
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

        Self::from_bytes(buf)
    }

    /// Write this certificate into the YubiKey in the given slot
    pub fn write(&self, yubikey: &mut YubiKey, slot: SlotId, certinfo: CertInfo) -> Result<()> {
        let txn = yubikey.begin_transaction()?;
        let data = self.cert.to_der().map_err(|_| Error::InvalidObject)?;
        write_certificate(&txn, slot, Some(&data), certinfo)
    }

    /// Delete a certificate located at the given slot of the given YubiKey
    #[cfg(feature = "untested")]
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

        x509_cert::Certificate::from_der(&cert)
            .map(|cert| Self { cert })
            .map_err(|_| Error::InvalidObject)
    }

    /// Returns the Issuer field of the certificate.
    pub fn issuer(&self) -> String {
        self.cert.tbs_certificate().issuer().to_string()
    }

    /// Returns the SubjectName field of the certificate.
    pub fn subject(&self) -> String {
        self.cert.tbs_certificate().subject().to_string()
    }

    /// Returns the SubjectPublicKeyInfo field of the certificate.
    pub fn subject_pki(&self) -> SubjectPublicKeyInfoRef<'_> {
        self.cert
            .tbs_certificate()
            .subject_public_key_info()
            .owned_to_ref()
    }
}

/// A [`BuilderProfile`] for self-signed certificates.
///
/// This profile has no default extensions.
pub struct SelfSigned {
    subject: Name,
}

impl BuilderProfile for SelfSigned {
    fn get_issuer(&self, subject: &Name) -> Name {
        // RFC 5280 Section 3.2:
        //
        // > Self-issued certificates are CA certificates in which the issuer and subject
        // > are the same entity. [..] Self-signed certificates are self-issued
        // > certificates where the digital signature may be verified by the public key
        // > bound into the certificate.
        subject.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &x509_cert::TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<x509_cert::ext::Extension>> {
        Ok(vec![])
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

    if let Some(data) = data {
        let mut buf = [0u8; CB_OBJ_MAX];
        let mut offset = Tlv::write(&mut buf, TAG_CERT, data)?;

        // write compression info and LRC trailer
        offset += Tlv::write(&mut buf[offset..], TAG_CERT_COMPRESS, &[certinfo.into()])?;
        offset += Tlv::write(&mut buf[offset..], TAG_CERT_LRC, &[])?;

        txn.save_object(object_id, &buf[..offset])
    } else {
        txn.save_object(object_id, &[])
    }
}

pub mod yubikey_signer {
    //! Signer implementation for yubikey

    use crate::{
        error::{Error, Result},
        piv::AlgorithmId,
        piv::{sign_data, SlotId},
        YubiKey,
    };
    use der::{
        asn1::{Any, OctetString},
        oid::db::rfc5912,
        Encode, Sequence,
    };
    use sha2::{Digest, Sha256, Sha384};
    use signature::Keypair;
    use std::{cell::RefCell, fmt, io::Write, marker::PhantomData};
    use x509_cert::spki::{
        self, AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, EncodePublicKey,
        SignatureBitStringEncoding, SubjectPublicKeyInfoRef,
    };

    type SigResult<T> = core::result::Result<T, signature::Error>;

    /// Key to be used to sign certificates
    pub trait KeyType {
        /// Error returned when working with signature
        type Error: Into<signature::Error> + fmt::Debug;
        /// The signature type returned by the signer
        type Signature: SignatureBitStringEncoding
            + for<'s> TryFrom<&'s [u8], Error = Self::Error>
            + fmt::Debug;
        /// The public key used to verify signature
        type VerifyingKey: EncodePublicKey
            + DynSignatureAlgorithmIdentifier
            + Clone
            + From<Self::PublicKey>;
        /// Public key type used to load the SPKI formatted key
        type PublicKey: for<'a> TryFrom<SubjectPublicKeyInfoRef<'a>, Error = spki::Error>;

        /// The algorithm used when talking with the yubikey
        const ALGORITHM: AlgorithmId;

        /// Prepare buffer before submitting it for signature
        fn prepare(input: &[u8]) -> SigResult<Vec<u8>>;
        /// Read back the signature from the device
        fn read_signature(input: &[u8]) -> SigResult<Self::Signature>;
    }

    impl KeyType for p256::NistP256 {
        const ALGORITHM: AlgorithmId = AlgorithmId::EccP256;
        type Error = ecdsa::Error;
        type Signature = p256::ecdsa::DerSignature;
        type VerifyingKey = p256::ecdsa::VerifyingKey;
        type PublicKey = p256::ecdsa::VerifyingKey;

        fn prepare(input: &[u8]) -> SigResult<Vec<u8>> {
            Ok(Sha256::digest(input).to_vec())
        }

        fn read_signature(input: &[u8]) -> SigResult<Self::Signature> {
            Self::Signature::from_bytes(input)
        }
    }

    impl KeyType for p384::NistP384 {
        const ALGORITHM: AlgorithmId = AlgorithmId::EccP384;
        type Error = ecdsa::Error;
        type Signature = p384::ecdsa::DerSignature;
        type VerifyingKey = p384::ecdsa::VerifyingKey;
        type PublicKey = p384::ecdsa::VerifyingKey;

        fn prepare(input: &[u8]) -> SigResult<Vec<u8>> {
            Ok(Sha384::digest(input).to_vec())
        }

        fn read_signature(input: &[u8]) -> SigResult<Self::Signature> {
            Self::Signature::from_bytes(input)
        }
    }

    /// Trait used to handle subtypes of RSA keys
    pub trait RsaLength {
        /// The length of the RSA key in bits
        const BIT_LENGTH: usize;
        /// The algorithm to use when talking with the Yubikey.
        const ALGORITHM: AlgorithmId;
    }

    /// RSA 1024 bits key
    pub struct Rsa1024;

    impl RsaLength for Rsa1024 {
        const BIT_LENGTH: usize = 1024;
        const ALGORITHM: AlgorithmId = AlgorithmId::Rsa1024;
    }

    /// RSA 2048 bits key
    pub struct Rsa2048;

    impl RsaLength for Rsa2048 {
        const BIT_LENGTH: usize = 2048;
        const ALGORITHM: AlgorithmId = AlgorithmId::Rsa2048;
    }

    /// RSA 3072 bits key
    pub struct Rsa3072;

    impl RsaLength for Rsa3072 {
        const BIT_LENGTH: usize = 3072;
        const ALGORITHM: AlgorithmId = AlgorithmId::Rsa3072;
    }

    /// RSA 4096 bits key
    pub struct Rsa4096;

    impl RsaLength for Rsa4096 {
        const BIT_LENGTH: usize = 4096;
        const ALGORITHM: AlgorithmId = AlgorithmId::Rsa4096;
    }

    /// RSA keys used to sign certificates
    pub struct YubiRsa<N: RsaLength> {
        _len: PhantomData<N>,
    }

    impl<N: RsaLength> KeyType for YubiRsa<N> {
        type Error = signature::Error;
        type Signature = rsa::pkcs1v15::Signature;
        type VerifyingKey = rsa::pkcs1v15::VerifyingKey<Sha256>;
        type PublicKey = rsa::RsaPublicKey;
        const ALGORITHM: AlgorithmId = N::ALGORITHM;

        fn prepare(input: &[u8]) -> SigResult<Vec<u8>> {
            let hashed = Sha256::digest(input).to_vec();

            OctetString::new(hashed)
                .map_err(|e| e.into())
                .and_then(Self::emsa_pkcs1_1_5)
                .map_err(signature::Error::from_source)
        }

        fn read_signature(input: &[u8]) -> SigResult<Self::Signature> {
            Self::Signature::try_from(input)
        }
    }

    impl<N: RsaLength> YubiRsa<N> {
        /// https://www.rfc-editor.org/rfc/rfc8017#section-9.2
        fn emsa_pkcs1_1_5(digest: OctetString) -> Result<Vec<u8>> {
            /// https://www.rfc-editor.org/rfc/rfc8017#appendix-A.2.4
            #[derive(Debug, Sequence)]
            struct DigestInfo {
                digest_algorithm: AlgorithmIdentifierOwned,
                digest: OctetString,
            }

            let em_len = N::BIT_LENGTH / 8;

            let null = Any::null();

            let t = DigestInfo {
                digest_algorithm: AlgorithmIdentifierOwned {
                    oid: rfc5912::ID_SHA_256,
                    parameters: Some(null),
                },
                digest,
            };
            let t = t.to_der()?;

            let ps = vec![0xff; em_len - t.len() - 3];
            assert!(ps.len() >= 8, "spec violation");

            let mut out = Vec::with_capacity(em_len);
            out.write(&[0x00, 0x01]).map_err(|_| Error::MemoryError)?;
            out.write(&ps).map_err(|_| Error::MemoryError)?;
            out.write(&[0x00]).map_err(|_| Error::MemoryError)?;
            out.write(&t).map_err(|_| Error::MemoryError)?;
            Ok(out)
        }
    }

    /// The entrypoint to sign data with the yubikey.
    pub struct Signer<'y, KT: KeyType> {
        yubikey: RefCell<&'y mut YubiKey>,
        key: SlotId,
        public_key: KT::VerifyingKey,
    }

    impl<'y, KT: KeyType> Signer<'y, KT> {
        /// Create new Signer
        pub fn new(
            yubikey: &'y mut YubiKey,
            key: SlotId,
            subject_pki: SubjectPublicKeyInfoRef<'_>,
        ) -> Result<Self> {
            let public_key = KT::PublicKey::try_from(subject_pki).map_err(|_| Error::ParseError)?;
            let public_key = public_key.into();

            Ok(Self {
                yubikey: RefCell::new(yubikey),
                key,
                public_key,
            })
        }
    }

    impl<KT: KeyType> Keypair for Signer<'_, KT> {
        type VerifyingKey = KT::VerifyingKey;
        fn verifying_key(&self) -> <Self as Keypair>::VerifyingKey {
            self.public_key.clone()
        }
    }

    impl<KT: KeyType> DynSignatureAlgorithmIdentifier for Signer<'_, KT> {
        fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
            self.verifying_key().signature_algorithm_identifier()
        }
    }

    impl<KT: KeyType> signature::Signer<KT::Signature> for Signer<'_, KT> {
        fn try_sign(&self, msg: &[u8]) -> SigResult<KT::Signature> {
            let data = KT::prepare(msg)?;

            let out = sign_data(
                &mut self.yubikey.borrow_mut(),
                &data,
                KT::ALGORITHM,
                self.key,
            )
            .map_err(signature::Error::from_source)?;
            let out = KT::read_signature(&out)?;
            Ok(out)
        }
    }
}
