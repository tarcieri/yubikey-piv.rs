//! Management Key (MGM) for authenticating to the YubiKey management applet

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
    yubikey::{Version, YubiKey},
    Error, Result,
};
use cipher::{typenum::Unsigned, BlockCipherDecrypt, BlockCipherEncrypt, Key, KeyInit};
use log::error;
use rand_core::CryptoRngCore;
use zeroize::Zeroize;

#[cfg(feature = "untested")]
use crate::{
    consts::{TAG_ADMIN_FLAGS_1, TAG_ADMIN_SALT, TAG_PROTECTED_MGM},
    metadata::{AdminData, ProtectedData},
    piv::{ManagementSlotId, SlotAlgorithmId},
    transaction::Transaction,
};
#[cfg(feature = "untested")]
use {pbkdf2::pbkdf2_hmac, sha1::Sha1};

/// YubiKey MGMT Applet Name
#[cfg(feature = "untested")]
pub(crate) const APPLET_NAME: &str = "YubiKey MGMT";

/// MGMT Applet ID.
///
/// <https://developers.yubico.com/PIV/Introduction/Admin_access.html>
#[cfg(feature = "untested")]
pub(crate) const APPLET_ID: &[u8] = &[0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

mod aes;
pub use aes::{MgmKeyAes128, MgmKeyAes192, MgmKeyAes256};

mod tdes;
pub use tdes::MgmKey3Des;

pub(crate) const ADMIN_FLAGS_1_PROTECTED_MGM: u8 = 0x02;

#[cfg(feature = "untested")]
const CB_ADMIN_SALT: usize = 16;

/// The default MGM key loaded for both Triple-DES and AES keys
#[cfg(feature = "untested")]
const DEFAULT_MGM_KEY: [u8; 24] = [
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
];

/// Number of PBKDF2 iterations to use when deriving from a password
#[cfg(feature = "untested")]
const ITER_MGM_PBKDF2: u32 = 10000;

/// Management Key (MGM) key types (manual/derived/protected).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MgmType {
    /// Manual
    Manual = 0,

    /// Derived
    Derived = 1,

    /// Protected
    Protected = 2,
}

/// Management key algorithm identifiers
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MgmAlgorithmId {
    /// Triple DES (3DES) in EDE mode
    ThreeDes,
    /// AES-128
    Aes128,
    /// AES-192
    Aes192,
    /// AES-256
    Aes256,
}

impl TryFrom<u8> for MgmAlgorithmId {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x03 => Ok(MgmAlgorithmId::ThreeDes),
            0x08 => Ok(MgmAlgorithmId::Aes128),
            0x0a => Ok(MgmAlgorithmId::Aes192),
            0x0c => Ok(MgmAlgorithmId::Aes256),
            _ => Err(Error::AlgorithmError),
        }
    }
}

impl From<MgmAlgorithmId> for u8 {
    fn from(id: MgmAlgorithmId) -> u8 {
        match id {
            MgmAlgorithmId::ThreeDes => 0x03,
            MgmAlgorithmId::Aes128 => 0x08,
            MgmAlgorithmId::Aes192 => 0x0a,
            MgmAlgorithmId::Aes256 => 0x0c,
        }
    }
}

impl MgmAlgorithmId {
    /// Looks up the algorithm for the given Yubikey's current management key.
    #[cfg(feature = "untested")]
    fn query(txn: &Transaction<'_>) -> Result<Self> {
        match txn.get_metadata(crate::piv::SlotId::Management(ManagementSlotId::Management)) {
            Ok(metadata) => match metadata.algorithm {
                SlotAlgorithmId::Management(alg) => Ok(alg),
                // We specifically queried the management key slot; getting a known
                // non-management algorithm back from the Yubikey is invalid.
                _ => Err(Error::InvalidObject),
            },
            // Firmware versions without `GET METADATA` only support 3DES.
            Err(Error::NotSupported) => Ok(MgmAlgorithmId::ThreeDes),
            // `Error::AlgorithmError` only occurs when a new algorithm is encountered.
            Err(Error::AlgorithmError) => Err(Error::NotSupported),
            // Raise other errors as-is.
            Err(e) => Err(e),
        }
    }
}

/// The algorithm used for the MGM key.
pub trait MgmKeyAlgorithm:
    BlockCipherDecrypt + BlockCipherEncrypt + Clone + KeyInit + private::Seal
{
    /// The algorithm ID used in APDU packets
    const ALGORITHM_ID: MgmAlgorithmId;

    /// Implemented by specializations to check if the key is weak.
    ///
    /// Returns an error if the key is weak.
    fn check_weak_key(_key: &Key<Self>) -> Result<()> {
        Ok(())
    }
}

/// Management Key (MGM).
///
/// This key is used to authenticate to the management applet running on
/// a YubiKey in order to perform administrative functions.
///
/// The only supported algorithm for MGM keys are 3DES and AES.
#[derive(Clone)]
pub struct MgmKey(MgmKeyKind);

#[derive(Clone)]
enum MgmKeyKind {
    Tdes(MgmKey3Des),
    Aes128(MgmKeyAes128),
    Aes192(MgmKeyAes192),
    Aes256(MgmKeyAes256),
}

impl MgmKey {
    /// Generates a random MGM key for the given algorithm.
    pub fn generate<C: MgmKeyAlgorithm>(rng: &mut impl CryptoRngCore) -> Result<Self> {
        match C::ALGORITHM_ID {
            MgmAlgorithmId::ThreeDes => MgmKey3Des::generate(rng).map(MgmKeyKind::Tdes),
            MgmAlgorithmId::Aes128 => MgmKeyAes128::generate(rng).map(MgmKeyKind::Aes128),
            MgmAlgorithmId::Aes192 => MgmKeyAes192::generate(rng).map(MgmKeyKind::Aes192),
            MgmAlgorithmId::Aes256 => MgmKeyAes256::generate(rng).map(MgmKeyKind::Aes256),
        }
        .map(Self)
    }

    /// Generates a random MGM key using the preferred algorithm for the given Yubikey's
    /// firmware version.
    pub fn generate_for(yubikey: &YubiKey, rng: &mut impl CryptoRngCore) -> Result<Self> {
        match yubikey.version() {
            // Initial firmware versions default to 3DES.
            Version { major: ..=4, .. }
            | Version {
                major: 5,
                minor: ..=6,
                ..
            } => MgmKey3Des::generate(rng).map(MgmKeyKind::Tdes),
            // Firmware 5.7.0 and above default to AES-192.
            Version {
                major: 5,
                minor: 7..,
                ..
            }
            | Version { major: 6.., .. } => MgmKeyAes192::generate(rng).map(MgmKeyKind::Aes192),
        }
        .map(Self)
    }

    /// Parses an MGM key from the given byte slice.
    ///
    /// Returns an error if the slice is the wrong size or the key is weak.
    ///
    /// TODO: Can we distinguish DES from AES-192? Or do we take `C` as a parameter and
    /// require the caller to know the type of the bytes they are parsing?
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        MgmKey3Des::from_bytes(bytes)
            .map(MgmKeyKind::Tdes)
            .map(Self)
    }

    /// Gets the default management key for the given Yubikey's firmware version.
    ///
    /// Returns an error if the Yubikey's default algorithm is unsupported.
    #[cfg(feature = "untested")]
    pub fn get_default(yubikey: &YubiKey) -> Result<Self> {
        match yubikey.version() {
            // Initial firmware versions default to 3DES.
            Version { major: ..=4, .. }
            | Version {
                major: 5,
                minor: ..=6,
                ..
            } => Ok(Self(MgmKeyKind::Tdes(
                MgmKey3Des::new(DEFAULT_MGM_KEY.into()).expect("valid"),
            ))),
            // Firmware 5.7.0 and above default to AES-192.
            Version {
                major: 5,
                minor: 7..,
                ..
            }
            | Version { major: 6.., .. } => Ok(Self(MgmKeyKind::Aes192(
                MgmKeyAes192::new(DEFAULT_MGM_KEY.into()).expect("valid"),
            ))),
        }
    }

    /// Derives a management key (MGM) with the given algorithm from a stored salt.
    ///
    /// TODO: Is this supported for AES? Is the algorithm supposed to be dynamic?
    #[cfg(feature = "untested")]
    pub fn get_derived(yubikey: &mut YubiKey, pin: &[u8]) -> Result<Self> {
        let txn = yubikey.begin_transaction()?;

        // Check the key algorithm.
        let alg = MgmAlgorithmId::query(&txn)?;
        if alg != MgmAlgorithmId::ThreeDes {
            return Err(Error::NotSupported);
        }

        // recover management key
        let admin_data = AdminData::read(&txn)?;
        let salt = admin_data.get_item(TAG_ADMIN_SALT)?;

        if salt.len() != CB_ADMIN_SALT {
            error!(
                "derived MGM salt exists, but is incorrect size: {} (expected {})",
                salt.len(),
                CB_ADMIN_SALT
            );

            return Err(Error::GenericError);
        }

        let mut mgm = Key::<des::TdesEde3>::default();
        pbkdf2_hmac::<Sha1>(pin, salt, ITER_MGM_PBKDF2, &mut mgm);
        MgmKey3Des::new(mgm).map(MgmKeyKind::Tdes).map(Self)
    }

    /// Resets the management key for the given YubiKey to the default value for that
    /// Yubikey's firmware version.
    ///
    /// This will wipe any metadata related to derived and PIN-protected management keys.
    #[cfg(feature = "untested")]
    pub fn set_default(yubikey: &mut YubiKey) -> Result<()> {
        Self::get_default(yubikey)?.set_manual(yubikey, false)
    }
}

/// Management Key (MGM).
///
/// This key is used to authenticate to the management applet running on
/// a YubiKey in order to perform administrative functions.
#[derive(Clone)]
pub struct SpecificMgmKey<C: MgmKeyAlgorithm>(Key<C>);

impl<C: MgmKeyAlgorithm> SpecificMgmKey<C> {
    /// Generates a random MGM key for this algorithm.
    pub fn generate(rng: &mut impl CryptoRngCore) -> Result<Self> {
        let key = C::generate_key_with_rng(rng).map_err(|e| {
            error!("RNG failure: {}", e);
            Error::KeyError
        })?;
        Ok(Self(key))
    }

    /// Parses an MGM key from the given byte slice.
    ///
    /// Returns an error if the slice is the wrong size or the key is weak.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let key = Key::<C>::try_from(bytes.as_ref()).map_err(|_| Error::SizeError)?;
        Self::new(key)
    }

    /// Creates an MGM key from the given key.
    ///
    /// Returns an error if the key is weak.
    pub fn new(key: Key<C>) -> Result<Self> {
        C::check_weak_key(&key)?;
        Ok(Self(key))
    }

    /// Derives a management key (MGM) from a stored salt.
    ///
    /// TODO: Is this supported generically, or only for TDES?
    #[cfg(feature = "untested")]
    pub fn get_derived(yubikey: &mut YubiKey, pin: &[u8]) -> Result<Self> {
        let txn = yubikey.begin_transaction()?;

        // Check the key algorithm.
        let alg = MgmAlgorithmId::query(&txn)?;
        if alg != MgmAlgorithmId::ThreeDes {
            return Err(Error::NotSupported);
        }

        // recover management key
        let admin_data = AdminData::read(&txn)?;
        let salt = admin_data.get_item(TAG_ADMIN_SALT)?;

        if salt.len() != CB_ADMIN_SALT {
            error!(
                "derived MGM salt exists, but is incorrect size: {} (expected {})",
                salt.len(),
                CB_ADMIN_SALT
            );

            return Err(Error::GenericError);
        }

        let mut mgm = Key::<C>::default();
        pbkdf2_hmac::<Sha1>(pin, salt, ITER_MGM_PBKDF2, &mut mgm);
        Self::new(mgm)
    }
}

/// The core operations available with a Management Key (MGM).
pub trait MgmKeyOps: AsRef<[u8]> + private::MgmKeyOpsInternal {
    /// Get protected management key (MGM)
    #[cfg(feature = "untested")]
    fn get_protected(yubikey: &mut YubiKey) -> Result<Self> {
        let txn = yubikey.begin_transaction()?;

        let alg = MgmAlgorithmId::query(&txn)?;

        let protected_data = ProtectedData::read(&txn)
            .inspect_err(|e| error!("could not read protected data (err: {:?})", e))?;

        let item = protected_data
            .get_item(TAG_PROTECTED_MGM)
            .inspect_err(|e| error!("could not read protected MGM from metadata (err: {:?})", e))?;

        Self::parse_key(alg, item).map_err(|e| match e {
            Error::SizeError => {
                error!(
                    "protected data contains MGM, but is the wrong size: {} (expected {:?})",
                    item.len(),
                    alg,
                );

                Error::AuthenticationError
            }
            _ => e,
        })
    }

    /// Configures the given YubiKey to use this management key.
    ///
    /// The management key must be stored by the user, and provided when performing key
    /// management operations.
    ///
    /// This will wipe any metadata related to derived and PIN-protected management keys.
    #[cfg(feature = "untested")]
    fn set_manual(&self, yubikey: &mut YubiKey, require_touch: bool) -> Result<()> {
        let txn = yubikey.begin_transaction()?;

        txn.set_mgm_key(self, require_touch)
            // Log a warning, since the device mgm key is corrupt or we're in a state
            // where we can't set the mgm key.
            .inspect_err(|e| error!("could not set new derived mgm key, err = {}", e))?;

        // After this point, we've set the mgm key, so the function should succeed,
        // regardless of being able to set the metadata.

        if let Ok(mut admin_data) = AdminData::read(&txn) {
            // Clear the protected mgm key bit.
            if let Ok(item) = admin_data.get_item(TAG_ADMIN_FLAGS_1) {
                let mut flags_1 = [0u8; 1];
                if item.len() == flags_1.len() {
                    flags_1.copy_from_slice(item);
                    flags_1[0] &= !ADMIN_FLAGS_1_PROTECTED_MGM;

                    if let Err(e) = admin_data.set_item(TAG_ADMIN_FLAGS_1, &flags_1) {
                        error!("could not set admin flags item, err = {}", e);
                    }
                } else {
                    error!(
                        "admin data flags are an incorrect size: {} (expected {})",
                        item.len(),
                        flags_1.len()
                    );
                }
            }

            // Remove any existing salt for a derived mgm key.
            if let Err(e) = admin_data.set_item(TAG_ADMIN_SALT, &[]) {
                error!("could not unset derived mgm salt (err = {})", e)
            }

            if let Err(e) = admin_data.write(&txn) {
                error!("could not write admin data, err = {}", e);
            }
        }

        // Clear any prior mgm key from protected data.
        if let Ok(mut protected_data) = ProtectedData::read(&txn) {
            if let Err(e) = protected_data.set_item(TAG_PROTECTED_MGM, &[]) {
                error!("could not clear protected mgm item, err = {:?}", e);
            } else if let Err(e) = protected_data.write(&txn) {
                error!("could not write protected data, err = {:?}", e);
            }
        }

        Ok(())
    }

    /// Configures the given YubiKey to use this as a PIN-protected management key.
    ///
    /// This enables key management operations to be performed with access to the PIN.
    #[cfg(feature = "untested")]
    fn set_protected(&self, yubikey: &mut YubiKey) -> Result<()> {
        let txn = yubikey.begin_transaction()?;

        txn.set_mgm_key(self, false)
            // log a warning, since the device mgm key is corrupt or we're in
            // a state where we can't set the mgm key
            .inspect_err(|e| error!("could not set new derived mgm key, err = {}", e))?;

        // after this point, we've set the mgm key, so the function should
        // succeed, regardless of being able to set the metadata

        // Fetch the current protected data, or start a blank metadata blob.
        let mut protected_data = ProtectedData::read(&txn).unwrap_or_default();

        // Set the new mgm key in protected data.
        if let Err(e) = protected_data.set_item(TAG_PROTECTED_MGM, self.as_ref()) {
            error!("could not set protected mgm item, err = {:?}", e);
        } else {
            protected_data
                .write(&txn)
                .inspect_err(|e| error!("could not write protected data, err = {:?}", e))?;
        }

        // set the protected mgm flag in admin data

        let mut flags_1 = [0u8; 1];

        let mut admin_data = if let Ok(mut admin_data) = AdminData::read(&txn) {
            if let Ok(item) = admin_data.get_item(TAG_ADMIN_FLAGS_1) {
                if item.len() == flags_1.len() {
                    flags_1.copy_from_slice(item);
                } else {
                    error!(
                        "admin data flags are an incorrect size: {} (expected {})",
                        item.len(),
                        flags_1.len()
                    );
                }
            } else {
                // flags are not set
                error!("admin data exists, but flags are not present");
            }

            // remove any existing salt
            if let Err(e) = admin_data.set_item(TAG_ADMIN_SALT, &[]) {
                error!("could not unset derived mgm salt (err = {})", e)
            }

            admin_data
        } else {
            AdminData::default()
        };

        flags_1[0] |= ADMIN_FLAGS_1_PROTECTED_MGM;

        if let Err(e) = admin_data.set_item(TAG_ADMIN_FLAGS_1, &flags_1) {
            error!("could not set admin flags item, err = {}", e);
        } else if let Err(e) = admin_data.write(&txn) {
            error!("could not write admin data, err = {}", e);
        }

        Ok(())
    }
}

impl<C: MgmKeyAlgorithm> private::MgmKeyOpsInternal for SpecificMgmKey<C> {
    fn algorithm_id(&self) -> MgmAlgorithmId {
        C::ALGORITHM_ID
    }

    fn key_size(&self) -> u8 {
        C::KeySize::U8
    }

    fn parse_key(alg: MgmAlgorithmId, bytes: impl AsRef<[u8]>) -> Result<Self> {
        if alg == C::ALGORITHM_ID {
            Self::from_bytes(bytes)
        } else {
            Err(Error::NotSupported)
        }
    }

    fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
        C::new(&self.0).encrypt_block(block.try_into().map_err(|_| Error::SizeError)?);
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
        C::new(&self.0).decrypt_block(block.try_into().map_err(|_| Error::SizeError)?);
        Ok(())
    }
}

impl private::MgmKeyOpsInternal for MgmKey {
    fn algorithm_id(&self) -> MgmAlgorithmId {
        match &self.0 {
            MgmKeyKind::Tdes(k) => k.algorithm_id(),
            MgmKeyKind::Aes128(k) => k.algorithm_id(),
            MgmKeyKind::Aes192(k) => k.algorithm_id(),
            MgmKeyKind::Aes256(k) => k.algorithm_id(),
        }
    }

    fn key_size(&self) -> u8 {
        match &self.0 {
            MgmKeyKind::Tdes(k) => k.key_size(),
            MgmKeyKind::Aes128(k) => k.key_size(),
            MgmKeyKind::Aes192(k) => k.key_size(),
            MgmKeyKind::Aes256(k) => k.key_size(),
        }
    }

    fn parse_key(alg: MgmAlgorithmId, bytes: impl AsRef<[u8]>) -> Result<Self> {
        match alg {
            MgmAlgorithmId::ThreeDes => MgmKey3Des::from_bytes(bytes).map(MgmKeyKind::Tdes),
            MgmAlgorithmId::Aes128 => MgmKeyAes128::from_bytes(bytes).map(MgmKeyKind::Aes128),
            MgmAlgorithmId::Aes192 => MgmKeyAes192::from_bytes(bytes).map(MgmKeyKind::Aes192),
            MgmAlgorithmId::Aes256 => MgmKeyAes256::from_bytes(bytes).map(MgmKeyKind::Aes256),
        }
        .map(Self)
    }

    fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
        match &self.0 {
            MgmKeyKind::Tdes(k) => k.encrypt_block(block),
            MgmKeyKind::Aes128(k) => k.encrypt_block(block),
            MgmKeyKind::Aes192(k) => k.encrypt_block(block),
            MgmKeyKind::Aes256(k) => k.encrypt_block(block),
        }
    }

    fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
        match &self.0 {
            MgmKeyKind::Tdes(k) => k.decrypt_block(block),
            MgmKeyKind::Aes128(k) => k.decrypt_block(block),
            MgmKeyKind::Aes192(k) => k.decrypt_block(block),
            MgmKeyKind::Aes256(k) => k.decrypt_block(block),
        }
    }
}

impl<C: MgmKeyAlgorithm> MgmKeyOps for SpecificMgmKey<C> {}

impl MgmKeyOps for MgmKey {}

impl<C: MgmKeyAlgorithm> AsRef<[u8]> for SpecificMgmKey<C> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<[u8]> for MgmKey {
    fn as_ref(&self) -> &[u8] {
        match &self.0 {
            MgmKeyKind::Tdes(k) => k.as_ref(),
            MgmKeyKind::Aes128(k) => k.as_ref(),
            MgmKeyKind::Aes192(k) => k.as_ref(),
            MgmKeyKind::Aes256(k) => k.as_ref(),
        }
    }
}

impl<C: MgmKeyAlgorithm> Drop for SpecificMgmKey<C> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<'a> TryFrom<&'a [u8]> for MgmKey {
    type Error = Error;

    fn try_from(key_bytes: &'a [u8]) -> Result<Self> {
        Self::from_bytes(key_bytes)
    }
}

/// Seals the [`MgmKeyAlgorithm`] and [`MgmKeyOps`] traits, and add some internal helpers.
mod private {
    use super::MgmAlgorithmId;
    use crate::{Error, Result};

    pub trait Seal {}
    impl Seal for des::TdesEde3 {}
    impl Seal for aes::Aes128 {}
    impl Seal for aes::Aes192 {}
    impl Seal for aes::Aes256 {}

    pub trait MgmKeyOpsInternal: Sized {
        /// Parses an MGM key from the given byte slice.
        ///
        /// Returns an error if the algorithm is unsupported, or the slice is the wrong size,
        /// or the key is weak.
        fn parse_key(alg: MgmAlgorithmId, bytes: impl AsRef<[u8]>) -> Result<Self>;

        /// Returns the ID used to identify the key algorithm with APDU packets.
        fn algorithm_id(&self) -> MgmAlgorithmId;

        /// Returns the key size in bytes.
        fn key_size(&self) -> u8;

        /// Encrypts a block with this key.
        ///
        /// Returns an error if the block is the wrong size.
        fn encrypt_block(&self, block: &mut [u8]) -> Result<()>;

        /// Decrypts a block with this key.
        ///
        /// Returns an error if the block is the wrong size.
        fn decrypt_block(&self, block: &mut [u8]) -> Result<()>;

        /// Given a challenge from a card, decrypts it and return the value
        fn card_challenge(&self, challenge: &[u8]) -> Result<Vec<u8>> {
            let mut output = challenge.to_owned();
            self.decrypt_block(output.as_mut_slice())?;
            Ok(output)
        }

        /// Checks the authentication matches the challenge and auth data
        fn check_challenge(&self, challenge: &[u8], auth_data: &[u8]) -> Result<()> {
            let mut response = challenge.to_owned();

            self.encrypt_block(response.as_mut_slice())?;

            use subtle::ConstantTimeEq;
            if response.ct_eq(auth_data).unwrap_u8() != 1 {
                return Err(Error::AuthenticationError);
            }

            Ok(())
        }
    }
}
