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

use crate::{Error, Result};
use log::error;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

#[cfg(feature = "untested")]
use crate::{
    consts::{TAG_ADMIN_FLAGS_1, TAG_ADMIN_SALT, TAG_PROTECTED_MGM},
    metadata::{AdminData, ProtectedData},
    piv::{ManagementSlotId, SlotAlgorithmId},
    transaction::Transaction,
    yubikey::YubiKey,
};
use des::{
    cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit},
    TdesEde3,
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

mod tdes;
pub(crate) use tdes::DES_LEN_3DES;
use tdes::DES_LEN_DES;

pub(crate) const ADMIN_FLAGS_1_PROTECTED_MGM: u8 = 0x02;

#[cfg(feature = "untested")]
const CB_ADMIN_SALT: usize = 16;

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
}

impl TryFrom<u8> for MgmAlgorithmId {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x03 => Ok(MgmAlgorithmId::ThreeDes),
            _ => Err(Error::AlgorithmError),
        }
    }
}

impl From<MgmAlgorithmId> for u8 {
    fn from(id: MgmAlgorithmId) -> u8 {
        match id {
            MgmAlgorithmId::ThreeDes => 0x03,
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

/// Management Key (MGM).
///
/// This key is used to authenticate to the management applet running on
/// a YubiKey in order to perform administrative functions.
///
/// The only supported algorithm for MGM keys is 3DES.
#[derive(Clone)]
pub struct MgmKey([u8; DES_LEN_3DES]);

impl MgmKey {
    /// Generate a random MGM key
    pub fn generate() -> Self {
        let mut key_bytes = [0u8; DES_LEN_3DES];
        OsRng.fill_bytes(&mut key_bytes);
        Self(key_bytes)
    }

    /// Create an MGM key from byte slice.
    ///
    /// Returns an error if the slice is the wrong size or the key is weak.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        bytes.as_ref().try_into()
    }

    /// Create an MGM key from the given byte array.
    ///
    /// Returns an error if the key is weak.
    pub fn new(key_bytes: [u8; DES_LEN_3DES]) -> Result<Self> {
        if tdes::is_weak_key(&key_bytes) {
            error!(
                "blacklisting key '{:?}' since it's weak (with odd parity)",
                &key_bytes
            );

            return Err(Error::KeyError);
        }

        Ok(Self(key_bytes))
    }

    /// Get derived management key (MGM)
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

        let mut mgm = [0u8; DES_LEN_3DES];
        pbkdf2_hmac::<Sha1>(pin, salt, ITER_MGM_PBKDF2, &mut mgm);
        MgmKey::from_bytes(mgm)
    }

    /// Get protected management key (MGM)
    #[cfg(feature = "untested")]
    pub fn get_protected(yubikey: &mut YubiKey) -> Result<Self> {
        let txn = yubikey.begin_transaction()?;

        // Check the key algorithm.
        let alg = MgmAlgorithmId::query(&txn)?;
        if alg != MgmAlgorithmId::ThreeDes {
            return Err(Error::NotSupported);
        }

        let protected_data = ProtectedData::read(&txn)
            .inspect_err(|e| error!("could not read protected data (err: {:?})", e))?;

        let item = protected_data
            .get_item(TAG_PROTECTED_MGM)
            .inspect_err(|e| error!("could not read protected MGM from metadata (err: {:?})", e))?;

        if item.len() != DES_LEN_3DES {
            error!(
                "protected data contains MGM, but is the wrong size: {} (expected {})",
                item.len(),
                DES_LEN_3DES
            );

            return Err(Error::AuthenticationError);
        }

        MgmKey::from_bytes(item)
    }

    /// Resets the management key for the given YubiKey to the default value.
    ///
    /// This will wipe any metadata related to derived and PIN-protected management keys.
    #[cfg(feature = "untested")]
    pub fn set_default(yubikey: &mut YubiKey) -> Result<()> {
        MgmKey::default().set_manual(yubikey, false)
    }

    /// Configures the given YubiKey to use this management key.
    ///
    /// The management key must be stored by the user, and provided when performing key
    /// management operations.
    ///
    /// This will wipe any metadata related to derived and PIN-protected management keys.
    #[cfg(feature = "untested")]
    pub fn set_manual(&self, yubikey: &mut YubiKey, require_touch: bool) -> Result<()> {
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
    pub fn set_protected(&self, yubikey: &mut YubiKey) -> Result<()> {
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

    /// Encrypt with 3DES key
    pub(crate) fn encrypt(&self, input: &[u8; DES_LEN_DES]) -> [u8; DES_LEN_DES] {
        let mut output = input.to_owned();
        TdesEde3::new(&self.0.into()).encrypt_block((&mut output).into());
        output
    }

    /// Decrypt with 3DES key
    pub(crate) fn decrypt(&self, input: &[u8; DES_LEN_DES]) -> [u8; DES_LEN_DES] {
        let mut output = input.to_owned();
        TdesEde3::new(&self.0.into()).decrypt_block((&mut output).into());
        output
    }
}

impl AsRef<[u8; DES_LEN_3DES]> for MgmKey {
    fn as_ref(&self) -> &[u8; DES_LEN_3DES] {
        &self.0
    }
}

/// Default MGM key configured on all YubiKeys
impl Default for MgmKey {
    fn default() -> Self {
        MgmKey([
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
        ])
    }
}

impl Drop for MgmKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<'a> TryFrom<&'a [u8]> for MgmKey {
    type Error = Error;

    fn try_from(key_bytes: &'a [u8]) -> Result<Self> {
        Self::new(key_bytes.try_into().map_err(|_| Error::SizeError)?)
    }
}
