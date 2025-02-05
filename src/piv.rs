//! Personal Identity Verification (PIV) cryptographic keys stored in a YubiKey.
//!
//! Support for public-key cryptography using keys stored within the PIV
//! slots of a YubiKey.
//!
//! Supported algorithms:
//!
//! - **Encryption**:
//!   - RSA: `RSA1024`, `RSA2048`, `RSA3072`, `RSA4096`
//!   - ECC: `ECCP256`, `ECCP384` (NIST curves: P-256, P-384)
//! - **Signatures**:
//!   - RSASSA-PKCS#1v1.5: `RSA1024`, `RSA2048`, `RSA3072`, `RSA4096`
//!   - ECDSA: `ECCP256`, `ECCP384` (NIST curves: P-256, P-384)

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
    apdu::{Ins, StatusWords},
    certificate::{self, Certificate},
    consts::CB_OBJ_MAX,
    error::{Error, Result},
    policy::{PinPolicy, TouchPolicy},
    serialization::*,
    setting,
    yubikey::YubiKey,
    Buffer, ObjectId,
};
use elliptic_curve::{sec1::EncodedPoint as EcPublicKey, PublicKey};
use log::{debug, error, warn};
use p256::NistP256;
use p384::NistP384;
use rsa::{pkcs8::EncodePublicKey, BigUint, RsaPublicKey};
use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};
use x509_cert::{der::Decode, spki::SubjectPublicKeyInfoOwned};

#[cfg(feature = "untested")]
use {
    num_bigint_dig::traits::ModInverse,
    num_integer::Integer,
    num_traits::{FromPrimitive, One},
};

#[cfg(feature = "untested")]
use zeroize::Zeroizing;

/// PIV Applet Name
pub(crate) const APPLET_NAME: &str = "PIV";

/// PIV Applet ID
pub(crate) const APPLET_ID: &[u8] = &[0xa0, 0x00, 0x00, 0x03, 0x08];

const CB_ECC_POINTP256: usize = 65;
const CB_ECC_POINTP384: usize = 97;

const TAG_RSA_MODULUS: u8 = 0x81;
const TAG_RSA_EXP: u8 = 0x82;
const TAG_ECC_POINT: u8 = 0x86;

#[cfg(feature = "untested")]
const KEYDATA_LEN: usize = 1024;

#[cfg(feature = "untested")]
const KEYDATA_RSA_EXP: u64 = 65537;

/// Slot identifiers.
/// <https://developers.yubico.com/PIV/Introduction/Certificate_slots.html>
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub enum SlotId {
    /// This certificate and its associated private key is used to authenticate the card
    /// and the cardholder. This slot is used for things like system login. The end user
    /// PIN is required to perform any private key operations. Once the PIN has been
    /// provided successfully, multiple private key operations may be performed without
    /// additional cardholder consent.
    Authentication,

    /// This certificate and its associated private key is used for digital signatures for
    /// the purpose of document signing, or signing files and executables. The end user
    /// PIN is required to perform any private key operations. The PIN must be submitted
    /// every time immediately before a sign operation, to ensure cardholder participation
    /// for every digital signature generated.
    Signature,

    /// This certificate and its associated private key is used for encryption for the
    /// purpose of confidentiality. This slot is used for things like encrypting e-mails
    /// or files. The end user PIN is required to perform any private key operations. Once
    /// the PIN has been provided successfully, multiple private key operations may be
    /// performed without additional cardholder consent.
    KeyManagement,

    /// This certificate and its associated private key is used to support additional
    /// physical access applications, such as providing physical access to buildings via
    /// PIV-enabled door locks. The end user PIN is NOT required to perform private key
    /// operations for this slot.
    CardAuthentication,

    /// These slots are only available on the YubiKey 4 & 5. They are meant for previously
    /// used Key Management keys to be able to decrypt earlier encrypted documents or
    /// emails. In the YubiKey 4 & 5 all 20 of them are fully available for use.
    Retired(RetiredSlotId),

    /// This slot is only available on YubiKey version 4.3 and newer. It is only used for
    /// attestation of other keys generated on device with instruction `f9`. This slot is
    /// not cleared on reset, but can be overwritten.
    Attestation,

    /// Thse slots are used for management. PIN PUK and Management Key.
    Management(ManagementSlotId),
}

impl TryFrom<u8> for SlotId {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x9a => Ok(SlotId::Authentication),
            0x9c => Ok(SlotId::Signature),
            0x9d => Ok(SlotId::KeyManagement),
            0x9e => Ok(SlotId::CardAuthentication),
            0xf9 => Ok(SlotId::Attestation),
            _ => RetiredSlotId::try_from(value)
                .map(SlotId::Retired)
                .or_else(|_| ManagementSlotId::try_from(value).map(SlotId::Management)),
        }
    }
}

impl From<SlotId> for u8 {
    fn from(slot: SlotId) -> u8 {
        match slot {
            SlotId::Authentication => 0x9a,
            SlotId::Signature => 0x9c,
            SlotId::KeyManagement => 0x9d,
            SlotId::CardAuthentication => 0x9e,
            SlotId::Retired(retired) => retired.into(),
            SlotId::Attestation => 0xf9,
            SlotId::Management(mgmt) => mgmt.into(),
        }
    }
}

impl Display for SlotId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SlotId::Management(r) => write!(f, "{:?}", r),
            SlotId::Retired(r) => write!(f, "{:?}", r),
            _ => write!(f, "{:?}", self),
        }
    }
}

impl FromStr for SlotId {
    type Err = Error;

    fn from_str(s: &str) -> Result<SlotId> {
        match s {
            "9a" => Ok(SlotId::Authentication),
            "9c" => Ok(SlotId::Signature),
            "9d" => Ok(SlotId::KeyManagement),
            "9e" => Ok(SlotId::CardAuthentication),
            "f9" => Ok(SlotId::Attestation),
            _ => s
                .parse()
                .map(SlotId::Management)
                .or_else(|_| s.parse().map(SlotId::Retired)),
        }
    }
}

impl SlotId {
    /// Returns the [`ObjectId`] that corresponds to a given [`SlotId`].
    pub(crate) fn object_id(self) -> ObjectId {
        match self {
            SlotId::Authentication => 0x005f_c105,
            SlotId::Signature => 0x005f_c10a,
            SlotId::KeyManagement => 0x005f_c10b,
            SlotId::CardAuthentication => 0x005f_c101,
            SlotId::Retired(retired) => retired.object_id(),
            SlotId::Management(mgmt) => mgmt.object_id(),
            SlotId::Attestation => 0x005f_ff01,
        }
    }
}

/// Retired slot IDs.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RetiredSlotId {
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    R16,
    R17,
    R18,
    R19,
    R20,
}

impl TryFrom<u8> for RetiredSlotId {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x82 => Ok(RetiredSlotId::R1),
            0x83 => Ok(RetiredSlotId::R2),
            0x84 => Ok(RetiredSlotId::R3),
            0x85 => Ok(RetiredSlotId::R4),
            0x86 => Ok(RetiredSlotId::R5),
            0x87 => Ok(RetiredSlotId::R6),
            0x88 => Ok(RetiredSlotId::R7),
            0x89 => Ok(RetiredSlotId::R8),
            0x8a => Ok(RetiredSlotId::R9),
            0x8b => Ok(RetiredSlotId::R10),
            0x8c => Ok(RetiredSlotId::R11),
            0x8d => Ok(RetiredSlotId::R12),
            0x8e => Ok(RetiredSlotId::R13),
            0x8f => Ok(RetiredSlotId::R14),
            0x90 => Ok(RetiredSlotId::R15),
            0x91 => Ok(RetiredSlotId::R16),
            0x92 => Ok(RetiredSlotId::R17),
            0x93 => Ok(RetiredSlotId::R18),
            0x94 => Ok(RetiredSlotId::R19),
            0x95 => Ok(RetiredSlotId::R20),
            _ => Err(Error::InvalidObject),
        }
    }
}

impl FromStr for RetiredSlotId {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "82" => Ok(RetiredSlotId::R1),
            "83" => Ok(RetiredSlotId::R2),
            "84" => Ok(RetiredSlotId::R3),
            "85" => Ok(RetiredSlotId::R4),
            "86" => Ok(RetiredSlotId::R5),
            "87" => Ok(RetiredSlotId::R6),
            "88" => Ok(RetiredSlotId::R7),
            "89" => Ok(RetiredSlotId::R8),
            "8a" => Ok(RetiredSlotId::R9),
            "8b" => Ok(RetiredSlotId::R10),
            "8c" => Ok(RetiredSlotId::R11),
            "8d" => Ok(RetiredSlotId::R12),
            "8e" => Ok(RetiredSlotId::R13),
            "8f" => Ok(RetiredSlotId::R14),
            "90" => Ok(RetiredSlotId::R15),
            "91" => Ok(RetiredSlotId::R16),
            "92" => Ok(RetiredSlotId::R17),
            "93" => Ok(RetiredSlotId::R18),
            "94" => Ok(RetiredSlotId::R19),
            "95" => Ok(RetiredSlotId::R20),
            _ => Err(Error::InvalidObject),
        }
    }
}

impl From<RetiredSlotId> for u8 {
    fn from(slot: RetiredSlotId) -> u8 {
        match slot {
            RetiredSlotId::R1 => 0x82,
            RetiredSlotId::R2 => 0x83,
            RetiredSlotId::R3 => 0x84,
            RetiredSlotId::R4 => 0x85,
            RetiredSlotId::R5 => 0x86,
            RetiredSlotId::R6 => 0x87,
            RetiredSlotId::R7 => 0x88,
            RetiredSlotId::R8 => 0x89,
            RetiredSlotId::R9 => 0x8a,
            RetiredSlotId::R10 => 0x8b,
            RetiredSlotId::R11 => 0x8c,
            RetiredSlotId::R12 => 0x8d,
            RetiredSlotId::R13 => 0x8e,
            RetiredSlotId::R14 => 0x8f,
            RetiredSlotId::R15 => 0x90,
            RetiredSlotId::R16 => 0x91,
            RetiredSlotId::R17 => 0x92,
            RetiredSlotId::R18 => 0x93,
            RetiredSlotId::R19 => 0x94,
            RetiredSlotId::R20 => 0x95,
        }
    }
}

impl Display for RetiredSlotId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl RetiredSlotId {
    /// Returns the [`ObjectId`] that corresponds to a given [`RetiredSlotId`].
    pub(crate) fn object_id(self) -> ObjectId {
        match self {
            RetiredSlotId::R1 => 0x005f_c10d,
            RetiredSlotId::R2 => 0x005f_c10e,
            RetiredSlotId::R3 => 0x005f_c10f,
            RetiredSlotId::R4 => 0x005f_c110,
            RetiredSlotId::R5 => 0x005f_c111,
            RetiredSlotId::R6 => 0x005f_c112,
            RetiredSlotId::R7 => 0x005f_c113,
            RetiredSlotId::R8 => 0x005f_c114,
            RetiredSlotId::R9 => 0x005f_c115,
            RetiredSlotId::R10 => 0x005f_c116,
            RetiredSlotId::R11 => 0x005f_c117,
            RetiredSlotId::R12 => 0x005f_c118,
            RetiredSlotId::R13 => 0x005f_c119,
            RetiredSlotId::R14 => 0x005f_c11a,
            RetiredSlotId::R15 => 0x005f_c11b,
            RetiredSlotId::R16 => 0x005f_c11c,
            RetiredSlotId::R17 => 0x005f_c11d,
            RetiredSlotId::R18 => 0x005f_c11e,
            RetiredSlotId::R19 => 0x005f_c11f,
            RetiredSlotId::R20 => 0x005f_c120,
        }
    }
}

/// Management slot IDs.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub enum ManagementSlotId {
    /// Personal Identification Number (PIN).
    Pin,

    /// PIN Unblocking Key (PUK).
    Puk,

    /// Management Key.
    Management,
}

impl TryFrom<u8> for ManagementSlotId {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x80 => Ok(ManagementSlotId::Pin),
            0x81 => Ok(ManagementSlotId::Puk),
            0x9b => Ok(ManagementSlotId::Management),
            _ => Err(Error::InvalidObject),
        }
    }
}

impl FromStr for ManagementSlotId {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "80" => Ok(ManagementSlotId::Pin),
            "81" => Ok(ManagementSlotId::Puk),
            "9b" => Ok(ManagementSlotId::Management),
            _ => Err(Error::InvalidObject),
        }
    }
}

impl From<ManagementSlotId> for u8 {
    fn from(slot: ManagementSlotId) -> u8 {
        match slot {
            ManagementSlotId::Pin => 0x80,
            ManagementSlotId::Puk => 0x81,
            ManagementSlotId::Management => 0x9b,
        }
    }
}

impl Display for ManagementSlotId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl ManagementSlotId {
    /// Returns the [`ObjectId`] that corresponds to a given [`ManagementSlotId`].
    ///
    /// These correspond to the "BER-TLV Tag" values from Table 3 of [NIST SP 800-73-4]:
    /// "Object Identifiers of the PIV Data Objects for Interoperable Use".
    ///
    /// [NIST SP 800-73-4]: https://csrc.nist.gov/publications/detail/sp/800-73/4/final
    pub(crate) fn object_id(self) -> ObjectId {
        match self {
            // Data Object: "X.509 Certificate for Key Management"
            // OID: 2.16.840.1.101.3.7.2.1.2
            // BER-TLV Tag: '5FC10B'
            ManagementSlotId::Pin => 0x005f_c10b,

            // Data Object: "Key History Object"
            // OID: 2.16.840.1.101.3.7.2.96.96
            // BER-TLV Tag: '5FC10C'
            ManagementSlotId::Puk => 0x005f_c10c,

            // Data Object: "Retired X.509 Certificate for Key Management 3"
            // OID: 2.16.840.1.101.3.7.2.16.3
            // BER-TLV Tag: '5FC10F'
            ManagementSlotId::Management => 0x005f_c10f,
        }
    }
}

/// Personal Identity Verification (PIV) key slots
pub const SLOTS: [SlotId; 28] = [
    SlotId::Authentication,
    SlotId::Signature,
    SlotId::KeyManagement,
    SlotId::Attestation,
    SlotId::Retired(RetiredSlotId::R1),
    SlotId::Retired(RetiredSlotId::R2),
    SlotId::Retired(RetiredSlotId::R3),
    SlotId::Retired(RetiredSlotId::R4),
    SlotId::Retired(RetiredSlotId::R5),
    SlotId::Retired(RetiredSlotId::R6),
    SlotId::Retired(RetiredSlotId::R7),
    SlotId::Retired(RetiredSlotId::R8),
    SlotId::Retired(RetiredSlotId::R9),
    SlotId::Retired(RetiredSlotId::R10),
    SlotId::Retired(RetiredSlotId::R11),
    SlotId::Retired(RetiredSlotId::R12),
    SlotId::Retired(RetiredSlotId::R13),
    SlotId::Retired(RetiredSlotId::R14),
    SlotId::Retired(RetiredSlotId::R15),
    SlotId::Retired(RetiredSlotId::R16),
    SlotId::Retired(RetiredSlotId::R17),
    SlotId::Retired(RetiredSlotId::R18),
    SlotId::Retired(RetiredSlotId::R19),
    SlotId::Retired(RetiredSlotId::R20),
    SlotId::CardAuthentication,
    SlotId::Management(ManagementSlotId::Pin),
    SlotId::Management(ManagementSlotId::Puk),
    SlotId::Management(ManagementSlotId::Management),
];

/// Algorithm identifiers
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlgorithmId {
    /// 1024-bit RSA.
    Rsa1024,

    /// 2048-bit RSA.
    Rsa2048,

    /// 3072-bit RSA. Requires firmware 5.7 or newer
    Rsa3072,

    /// 4096-bit RSA. Requires firmware 5.7 or newer
    Rsa4096,

    /// ECDSA with the NIST P256 curve.
    EccP256,

    /// ECDSA with the NIST P384 curve.
    EccP384,
}

impl TryFrom<u8> for AlgorithmId {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x06 => Ok(AlgorithmId::Rsa1024),
            0x07 => Ok(AlgorithmId::Rsa2048),
            0x05 => Ok(AlgorithmId::Rsa3072),
            0x16 => Ok(AlgorithmId::Rsa4096),
            0x11 => Ok(AlgorithmId::EccP256),
            0x14 => Ok(AlgorithmId::EccP384),
            _ => Err(Error::AlgorithmError),
        }
    }
}

impl From<AlgorithmId> for u8 {
    fn from(id: AlgorithmId) -> u8 {
        match id {
            AlgorithmId::Rsa1024 => 0x06,
            AlgorithmId::Rsa2048 => 0x07,
            AlgorithmId::Rsa3072 => 0x05,
            AlgorithmId::Rsa4096 => 0x16,
            AlgorithmId::EccP256 => 0x11,
            AlgorithmId::EccP384 => 0x14,
        }
    }
}

impl AlgorithmId {
    /// Writes the `AlgorithmId` in the format the YubiKey expects during key generation.
    pub(crate) fn write(self, buf: &mut [u8]) -> Result<usize> {
        Tlv::write(buf, 0x80, &[self.into()])
    }

    #[cfg(feature = "untested")]
    fn get_elem_len(self) -> usize {
        match self {
            AlgorithmId::Rsa1024 => 64,
            AlgorithmId::Rsa2048 => 128,
            AlgorithmId::Rsa3072 => 192,
            AlgorithmId::Rsa4096 => 256,
            AlgorithmId::EccP256 => 32,
            AlgorithmId::EccP384 => 48,
        }
    }

    #[cfg(feature = "untested")]
    fn get_param_tag(self) -> u8 {
        match self {
            AlgorithmId::Rsa1024
            | AlgorithmId::Rsa2048
            | AlgorithmId::Rsa3072
            | AlgorithmId::Rsa4096 => 0x01,
            AlgorithmId::EccP256 | AlgorithmId::EccP384 => 0x6,
        }
    }
}

/// PIV cryptographic keys stored in a YubiKey
#[derive(Clone, Debug)]
pub struct Key {
    /// Card slot
    slot: SlotId,

    /// Cert
    cert: Certificate,
}

impl Key {
    /// List Personal Identity Verification (PIV) keys stored in a YubiKey
    pub fn list(yubikey: &mut YubiKey) -> Result<Vec<Self>> {
        let mut keys = vec![];
        let txn = yubikey.begin_transaction()?;

        for slot in SLOTS.iter().cloned() {
            let buf = match certificate::read_certificate(&txn, slot) {
                Ok(b) => b,
                Err(e) => {
                    debug!("error reading certificate in slot {:?}: {}", slot, e);
                    continue;
                }
            };

            if !buf.is_empty() {
                let cert = Certificate::from_bytes(buf)?;
                keys.push(Key { slot, cert });
            }
        }

        Ok(keys)
    }

    /// Get the slot ID for this key
    pub fn slot(&self) -> SlotId {
        self.slot
    }

    /// Get the certificate for this key
    pub fn certificate(&self) -> &Certificate {
        &self.cert
    }
}

/// Generate new key.
pub fn generate(
    yubikey: &mut YubiKey,
    slot: SlotId,
    algorithm: AlgorithmId,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
) -> Result<SubjectPublicKeyInfoOwned> {
    // Keygen messages
    // TODO(tarcieri): extract these into an I18N-handling type?
    const SZ_SETTING_ROCA: &str = "Enable_Unsafe_Keygen_ROCA";
    const SZ_ROCA_ALLOW_USER: &str =
        "was permitted by an end-user configuration setting, but is not recommended.";
    const SZ_ROCA_ALLOW_ADMIN: &str =
        "was permitted by an administrator configuration setting, but is not recommended.";
    const SZ_ROCA_BLOCK_USER: &str = "was blocked due to an end-user configuration setting.";
    const SZ_ROCA_BLOCK_ADMIN: &str = "was blocked due to an administrator configuration setting.";
    const SZ_ROCA_DEFAULT: &str = "was permitted by default, but is not recommended.  The default behavior will change in a future Yubico release.";

    let setting_roca: setting::Setting;

    match algorithm {
        AlgorithmId::Rsa1024
        | AlgorithmId::Rsa2048
        | AlgorithmId::Rsa3072
        | AlgorithmId::Rsa4096 => {
            if yubikey.version.major == 4
                && (yubikey.version.minor < 3
                    || yubikey.version.minor == 3 && (yubikey.version.patch < 5))
            {
                setting_roca = setting::Setting::get(SZ_SETTING_ROCA, true);

                let psz_msg = match setting_roca.source {
                    setting::SettingSource::User => {
                        if setting_roca.value {
                            SZ_ROCA_ALLOW_USER
                        } else {
                            SZ_ROCA_BLOCK_USER
                        }
                    }
                    setting::SettingSource::Admin => {
                        if setting_roca.value {
                            SZ_ROCA_ALLOW_ADMIN
                        } else {
                            SZ_ROCA_BLOCK_ADMIN
                        }
                    }
                    _ => SZ_ROCA_DEFAULT,
                };

                warn!(
                    "YubiKey serial number {} is affected by vulnerability CVE-2017-15361 \
                     (ROCA) and should be replaced. On-chip key generation {}  See \
                     YSA-2017-01 <https://www.yubico.com/support/security-advisories/ysa-2017-01/> \
                     for additional information on device replacement and mitigation assistance",
                    yubikey.serial, psz_msg
                );

                if !setting_roca.value {
                    return Err(Error::NotSupported);
                }
            }
        }
        _ => (),
    }

    let txn = yubikey.begin_transaction()?;

    let templ = [0, Ins::GenerateAsymmetric.code(), 0, slot.into()];

    let mut in_data = [0u8; 11];
    let mut offset = Tlv::write_as(&mut in_data, 0xac, 3, |buf| {
        assert_eq!(algorithm.write(buf).expect("large enough"), 3);
    })?;

    let pin_len = pin_policy.write(&mut in_data[offset..])?;
    in_data[1] += pin_len as u8;
    offset += pin_len;

    let touch_len = touch_policy.write(&mut in_data[offset..])?;
    in_data[1] += touch_len as u8;
    offset += touch_len;

    let response = txn.transfer_data(&templ, &in_data[..offset], 1024)?;

    if !response.is_success() {
        let err_msg = "failed to generate new key";

        match response.status_words() {
            StatusWords::IncorrectSlotError => {
                error!("{} (incorrect slot)", err_msg);
                return Err(Error::KeyError);
            }
            StatusWords::IncorrectParamError => {
                match pin_policy {
                    PinPolicy::Default => match touch_policy {
                        TouchPolicy::Default => error!("{} (algorithm not supported?)", err_msg),
                        _ => error!("{} (touch policy not supported?)", err_msg),
                    },
                    _ => error!("{} (pin policy not supported?)", err_msg),
                }

                return Err(Error::AlgorithmError);
            }
            StatusWords::SecurityStatusError => {
                error!("{} (not authenticated)", err_msg);
                return Err(Error::AuthenticationError);
            }
            other => {
                error!("{} (error {:?})", err_msg, other);
                return Err(Error::GenericError);
            }
        }
    }

    let value = response.data();
    read_public_key(algorithm, value, true)
}

#[cfg(feature = "untested")]
fn write_key(
    yubikey: &mut YubiKey,
    slot: SlotId,
    params: Vec<&[u8]>,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
    algorithm: AlgorithmId,
) -> Result<()> {
    let mut key_data = Buffer::new(vec![0u8; KEYDATA_LEN]);
    let templ = [0, Ins::ImportKey.code(), algorithm.into(), slot.into()];
    let mut offset = 0;

    let elem_len = algorithm.get_elem_len();
    let param_tag = algorithm.get_param_tag();

    for (i, param) in params.into_iter().enumerate() {
        offset += Tlv::write_as(
            &mut key_data[offset..],
            param_tag + (i as u8),
            elem_len,
            |buf| {
                let padding = elem_len - param.len();
                for b in &mut buf[..padding] {
                    *b = 0;
                }
                buf[padding..].copy_from_slice(param);
            },
        )?;
    }

    offset += pin_policy.write(&mut key_data[offset..])?;
    offset += touch_policy.write(&mut key_data[offset..])?;

    let txn = yubikey.begin_transaction()?;

    let status_words = txn
        .transfer_data(&templ, &key_data[..offset], 256)?
        .status_words();

    match status_words {
        StatusWords::Success => Ok(()),
        StatusWords::SecurityStatusError => Err(Error::AuthenticationError),
        _ => Err(Error::GenericError),
    }
}

/// The key data that makes up an RSA key.
#[cfg(feature = "untested")]
pub struct RsaKeyData {
    /// The secret prime `p`.
    p: Buffer,
    /// The secret prime, `q`.
    q: Buffer,
    /// D mod (P-1)
    dp: Buffer,
    /// D mod (Q-1)
    dq: Buffer,
    /// Q^-1 mod P
    qinv: Buffer,
}

#[cfg(feature = "untested")]
impl RsaKeyData {
    /// Generates a new RSA key data set from two (randomly generated) secret primes.
    ///
    /// # Returns
    /// - `Ok(key_data)` if `secret_p` and `secret_q` are valid primes.
    /// - `Err(Error::AlgorithmError)` if `secret_p`/`secret_q` are invalid primes.
    pub fn new(secret_p: &[u8], secret_q: &[u8]) -> Result<Self> {
        let p = BigUint::from_bytes_be(secret_p);
        let q = BigUint::from_bytes_be(secret_q);

        let totient = {
            let p_t = &p - BigUint::one();
            let q_t = &p - BigUint::one();

            p_t.lcm(&q_t)
        };

        let exp = BigUint::from_u64(KEYDATA_RSA_EXP).ok_or(Error::AlgorithmError)?;

        let d = exp.mod_inverse(&totient).ok_or(Error::AlgorithmError)?;
        let d = d.to_biguint().ok_or(Error::AlgorithmError)?;

        // We calculate the optimization values ahead of time, instead of making the user
        // do so.

        let dp = &d % (&p - BigUint::one());
        let dq = &d % (&q - BigUint::one());

        let qinv = q.clone().mod_inverse(&p).ok_or(Error::AlgorithmError)?;
        let (_, qinv) = qinv.to_bytes_be();

        Ok(RsaKeyData {
            p: Zeroizing::new(p.to_bytes_be()),
            q: Zeroizing::new(q.to_bytes_be()),
            dp: Zeroizing::new(dp.to_bytes_be()),
            dq: Zeroizing::new(dq.to_bytes_be()),
            qinv: Zeroizing::new(qinv),
        })
    }

    fn total_len(&self) -> usize {
        self.p.len() + self.q.len() + self.dp.len() + self.qinv.len()
    }
}

/// Imports a private RSA encryption or signing key into the YubiKey.
///
/// Errors if `algorithm` isn't `AlgorithmId::Rsa1024` or `AlgorithmId::Rsa2048` or `AlgorithmId::Rsa3072` or `AlgorithmId::Rsa4096`.
#[cfg(feature = "untested")]
pub fn import_rsa_key(
    yubikey: &mut YubiKey,
    slot: SlotId,
    algorithm: AlgorithmId,
    key_data: RsaKeyData,
    touch_policy: TouchPolicy,
    pin_policy: PinPolicy,
) -> Result<()> {
    match algorithm {
        AlgorithmId::Rsa1024
        | AlgorithmId::Rsa2048
        | AlgorithmId::Rsa3072
        | AlgorithmId::Rsa4096 => (),
        _ => return Err(Error::AlgorithmError),
    }

    if key_data.total_len() > KEYDATA_LEN {
        return Err(Error::SizeError);
    }

    let params = vec![
        key_data.p.as_slice(),
        key_data.q.as_slice(),
        key_data.dp.as_slice(),
        key_data.dq.as_slice(),
        key_data.qinv.as_slice(),
    ];

    write_key(yubikey, slot, params, pin_policy, touch_policy, algorithm)?;

    Ok(())
}

/// Imports a private ECC encryption or signing key into the YubiKey.
///
/// Errors if `algorithm` isn't `AlgorithmId::EccP256` or ` AlgorithmId::EccP384`.
#[cfg(feature = "untested")]
pub fn import_ecc_key(
    yubikey: &mut YubiKey,
    slot: SlotId,
    algorithm: AlgorithmId,
    key_data: &[u8],
    touch_policy: TouchPolicy,
    pin_policy: PinPolicy,
) -> Result<()> {
    match algorithm {
        AlgorithmId::EccP256 | AlgorithmId::EccP384 => (),
        _ => return Err(Error::AlgorithmError),
    }

    if key_data.len() > KEYDATA_LEN {
        return Err(Error::SizeError);
    }

    let params = vec![key_data];

    write_key(yubikey, slot, params, pin_policy, touch_policy, algorithm)?;

    Ok(())
}

/// Generate an attestation certificate for a stored key.
///
/// <https://developers.yubico.com/PIV/Introduction/PIV_attestation.html>
#[cfg(feature = "untested")]
pub fn attest(yubikey: &mut YubiKey, key: SlotId) -> Result<Buffer> {
    let templ = [0, Ins::Attest.code(), key.into(), 0];
    let txn = yubikey.begin_transaction()?;
    let response = txn.transfer_data(&templ, &[], CB_OBJ_MAX)?;

    if !response.is_success() {
        if response.status_words() == StatusWords::NotSupportedError {
            return Err(Error::NotSupported);
        } else {
            return Err(Error::GenericError);
        }
    }

    if response.data()[0] != 0x30 {
        return Err(Error::GenericError);
    }

    Ok(Buffer::new(response.data().into()))
}

/// Sign data using a PIV key.
pub fn sign_data(
    yubikey: &mut YubiKey,
    raw_in: &[u8],
    algorithm: AlgorithmId,
    key: SlotId,
) -> Result<Buffer> {
    let txn = yubikey.begin_transaction()?;

    // don't attempt to reselect in crypt operations to avoid problems with PIN_ALWAYS
    txn.authenticated_command(raw_in, algorithm, key, false)
}

/// Decrypt data using a PIV key.
#[cfg(feature = "untested")]
pub fn decrypt_data(
    yubikey: &mut YubiKey,
    input: &[u8],
    algorithm: AlgorithmId,
    key: SlotId,
) -> Result<Buffer> {
    let txn = yubikey.begin_transaction()?;

    // don't attempt to reselect in crypt operations to avoid problems with PIN_ALWAYS
    txn.authenticated_command(input, algorithm, key, true)
}

/// Read metadata
pub fn metadata(yubikey: &mut YubiKey, slot: SlotId) -> Result<SlotMetadata> {
    let txn = yubikey.begin_transaction()?;
    let templ = [0, Ins::GetMetadata.code(), 0, slot.into()];

    let response = txn.transfer_data(&templ, &[], CB_OBJ_MAX)?;

    if !response.is_success() {
        if response.status_words() == StatusWords::NotSupportedError {
            return Err(Error::NotSupported); // Requires firmware 5.2.3
        } else {
            return Err(Error::GenericError);
        }
    }

    let buf = Buffer::new(response.data().into());

    SlotMetadata::try_from(buf)
}

/// Metadata from a slot
#[derive(Debug)]
pub struct SlotMetadata {
    /// Algorithm / Type of key
    pub algorithm: ManagementAlgorithmId,
    /// PIN and touch policy
    pub policy: Option<(PinPolicy, TouchPolicy)>,
    /// Imported or generated key
    pub origin: Option<Origin>,
    /// Pub key of the key
    pub public: Option<SubjectPublicKeyInfoOwned>,
    /// Whether PIN PUK and management key are default
    pub default: Option<bool>,
    /// Number of retries left
    pub retries: Option<Retries>,
}

impl TryFrom<Buffer> for SlotMetadata {
    type Error = Error;

    fn try_from(buf: Buffer) -> Result<Self> {
        use nom::{
            combinator::{eof, map_res},
            multi::fold_many1,
            number::complete::u8,
        };

        let out = fold_many1(
            |input| Tlv::parse(input).map_err(|_| nom::Err::Error(())),
            || {
                Ok(SlotMetadata {
                    algorithm: ManagementAlgorithmId::PinPuk,
                    policy: None,
                    origin: None,
                    public: None,
                    default: None,
                    retries: None,
                })
            },
            |acc: Result<SlotMetadata>, tlv| match acc {
                Ok(mut metadata) => match tlv.tag {
                    1 => {
                        metadata.algorithm = ManagementAlgorithmId::try_from(tlv.value[0])?;
                        Ok(metadata)
                    }
                    2 => {
                        fn policy_parser(
                            i: &[u8],
                        ) -> nom::IResult<&[u8], (PinPolicy, TouchPolicy)> {
                            let (i, pin) = map_res(u8, PinPolicy::try_from)(i)?;
                            let (i, touch) = map_res(u8, TouchPolicy::try_from)(i)?;
                            let (i, _) = eof(i)?;

                            Ok((i, (pin, touch)))
                        }

                        metadata.policy =
                            Some(policy_parser(tlv.value).map_err(|_| Error::ParseError)?.1);
                        Ok(metadata)
                    }
                    3 => {
                        fn origin_parser(i: &[u8]) -> nom::IResult<&[u8], Origin> {
                            let (i, origin) = map_res(u8, Origin::try_from)(i)?;
                            let (i, _) = eof(i)?;

                            Ok((i, origin))
                        }

                        metadata.origin =
                            Some(origin_parser(tlv.value).map_err(|_| Error::ParseError)?.1);
                        Ok(metadata)
                    }
                    4 => {
                        match metadata.algorithm {
                            ManagementAlgorithmId::Asymmetric(alg) => {
                                metadata.public = Some(read_public_key(alg, tlv.value, false)?);
                            }
                            _ => Err(Error::ParseError)?,
                        }
                        Ok(metadata)
                    }
                    5 => {
                        fn default_parser(i: &[u8]) -> nom::IResult<&[u8], bool> {
                            let (i, default) = u8(i)?;
                            let (i, _) = eof(i)?;

                            Ok((i, default == 1))
                        }

                        metadata.default =
                            Some(default_parser(tlv.value).map_err(|_| Error::ParseError)?.1);
                        Ok(metadata)
                    }

                    6 => {
                        fn retries_parser(i: &[u8]) -> nom::IResult<&[u8], Retries> {
                            let (i, retry_count) = u8(i)?;
                            let (i, remaining_count) = u8(i)?;
                            let (i, _) = eof(i)?;

                            Ok((
                                i,
                                Retries {
                                    retry_count,
                                    remaining_count,
                                },
                            ))
                        }

                        metadata.retries =
                            Some(retries_parser(tlv.value).map_err(|_| Error::ParseError)?.1);
                        Ok(metadata)
                    }

                    _unsupported => {
                        // New unsupported tags
                        // https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/metadata.html
                        Ok(metadata)
                    }
                },
                err => err,
            },
        )(buf.as_ref());

        match out {
            Ok((_, res)) => res,
            _ => Err(Error::ParseError),
        }
    }
}

/// The number of retries used and remaining.
#[derive(Debug, PartialEq, Eq)]
pub struct Retries {
    /// TODO
    pub retry_count: u8,
    /// Remaining attempts
    pub remaining_count: u8,
}

/// Origin of a slot
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Origin {
    /// The key has been imported
    Imported,
    /// The key has been generated on the YubiKey
    Generated,
}

impl TryFrom<u8> for Origin {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Origin::Generated),
            2 => Ok(Origin::Imported),
            _ => Err(Error::GenericError),
        }
    }
}

fn read_public_key(
    algorithm: AlgorithmId,
    input: &[u8],
    skip_asn1_tag: bool,
) -> Result<SubjectPublicKeyInfoOwned> {
    // TODO(str4d): Response is wrapped in an ASN.1 TLV:
    //
    //    0x7f 0x49 -> Application | Constructed | 0x49
    match algorithm {
        AlgorithmId::Rsa1024
        | AlgorithmId::Rsa2048
        | AlgorithmId::Rsa3072
        | AlgorithmId::Rsa4096 => {
            // It appears that the inner application-specific value returned by the
            // YubiKey is constructed such that RSA pubkeys can be parsed in two ways:
            //
            // - Use a full ASN.1 parser on the entire datastructure:
            //
            //     RSA 1024:
            //     [127, 73, 129, 136, 129, 129, 128, [ 128 octets ], 130,  3, 1, 0, 1]
            //     | tag   | len:136 |0x81| len:128 |    modulus    |0x82|len3|  exp  |
            //
            //     RSA 2048:
            //     [127, 73, 130, 1, 9, 129, 130, 1, 0, [ 256 octets ], 130,  3, 1, 0, 1]
            //     | tag   | len:265  |0x81| len:256  |    modulus    |0x82|len3|  exp  |
            //
            // - Skip the first 5 bytes and use crate::serialize::get_length during TLV
            //   parsing (which treats 128 as a single-byte definite length instead of an
            //   indefinite length):
            //
            //     RSA 1024:
            //     [127, 73, 129, 136, 129, 129, 128, [ 128 octets ], 130,  3, 1, 0, 1]
            //     |                      |0x81|len128|   modulus   |0x82|len3|  exp  |
            //
            //     RSA 2048:
            //     [127, 73, 130, 1, 9, 129, 130, 1, 0, [ 256 octets ], 130,  3, 1, 0, 1]
            //     |                  |0x81| len:256  |    modulus    |0x82|len3|  exp  |
            //
            // Because of the above, treat this for now as a 2-byte ASN.1 tag with a
            // 3-byte length.
            let data = if skip_asn1_tag { &input[5..] } else { input };

            let (data, modulus_tlv) = Tlv::parse(data)?;
            if modulus_tlv.tag != TAG_RSA_MODULUS {
                error!("Failed to parse public key structure (modulus)");
                return Err(Error::ParseError);
            }
            let modulus = modulus_tlv.value.to_vec();

            let (_, exp_tlv) = Tlv::parse(data)?;
            if exp_tlv.tag != TAG_RSA_EXP {
                error!("failed to parse public key structure (public exponent)");
                return Err(Error::ParseError);
            }
            let exp = exp_tlv.value.to_vec();

            let pubkey = RsaPublicKey::new(
                BigUint::from_bytes_be(&modulus),
                BigUint::from_bytes_be(&exp),
            )
            .map_err(|_| Error::InvalidObject)?;
            Ok(SubjectPublicKeyInfoOwned::from_der(
                pubkey
                    .to_public_key_der()
                    .map_err(|_| Error::ParseError)?
                    .as_bytes(),
            )?)
        }
        AlgorithmId::EccP256 | AlgorithmId::EccP384 => {
            // 2-byte ASN.1 tag, 1-byte length (because all supported EC pubkey lengths
            // are shorter than 128 bytes, fitting into a definite short ASN.1 length).
            let data = if skip_asn1_tag { &input[3..] } else { input };

            let len = if let AlgorithmId::EccP256 = algorithm {
                CB_ECC_POINTP256
            } else {
                CB_ECC_POINTP384
            };

            let (_, tlv) = Tlv::parse(data)?;

            if tlv.tag != TAG_ECC_POINT {
                error!("failed to parse public key structure");
                return Err(Error::ParseError);
            }

            // the curve point should always be determined by the curve
            if tlv.value.len() != len {
                error!("unexpected length");
                return Err(Error::AlgorithmError);
            }

            let point = tlv.value.to_vec();

            let pubkey = match algorithm {
                AlgorithmId::EccP256 => PublicKey::<NistP256>::try_from(
                    EcPublicKey::<NistP256>::from_bytes(point).map_err(|_| Error::InvalidObject)?,
                )
                .map_err(|_| Error::InvalidObject)?
                .to_public_key_der(),
                AlgorithmId::EccP384 => PublicKey::<NistP384>::try_from(
                    EcPublicKey::<NistP384>::from_bytes(point).map_err(|_| Error::InvalidObject)?,
                )
                .map_err(|_| Error::InvalidObject)?
                .to_public_key_der(),
                _ => return Err(Error::AlgorithmError),
            }
            .map_err(|_| Error::InvalidObject)?;

            Ok(SubjectPublicKeyInfoOwned::from_der(pubkey.as_bytes())?)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Algorithms as reported by the metadata command.
pub enum ManagementAlgorithmId {
    /// Used on PIN and PUK slots.
    PinPuk,
    /// Used on the key management slot.
    ThreeDes,
    /// Used on all other slots.
    Asymmetric(AlgorithmId),
}

impl TryFrom<u8> for ManagementAlgorithmId {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0xff => Ok(ManagementAlgorithmId::PinPuk),
            0x03 => Ok(ManagementAlgorithmId::ThreeDes),
            oth => AlgorithmId::try_from(oth).map(ManagementAlgorithmId::Asymmetric),
        }
    }
}

impl From<ManagementAlgorithmId> for u8 {
    fn from(id: ManagementAlgorithmId) -> u8 {
        match id {
            ManagementAlgorithmId::PinPuk => 0xff,
            ManagementAlgorithmId::ThreeDes => 0x03,
            ManagementAlgorithmId::Asymmetric(oth) => oth.into(),
        }
    }
}
