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
use rand_core::OsRng;
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "untested")]
use crate::{
    consts::{TAG_ADMIN_FLAGS_1, TAG_ADMIN_SALT, TAG_PROTECTED_MGM},
    metadata::{AdminData, ProtectedData},
    yubikey::YubiKey,
};
use cipher::{
    crypto_common::{Key, KeyInit},
    generic_array::GenericArray,
    BlockCipher, BlockDecrypt, BlockEncrypt,
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

pub(crate) const ADMIN_FLAGS_1_PROTECTED_MGM: u8 = 0x02;

#[cfg(feature = "untested")]
const CB_ADMIN_SALT: usize = 16;

/// Size of a DES key
const DES_LEN_DES: usize = 8;

/// The default MGM key loaded for both Triple-DES and AES keys
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

/// The algorithm used for the MGM key.
pub trait MgmKeyAlgorithm:
    BlockCipher + BlockDecrypt + BlockEncrypt + Clone + KeyInit + private::Seal
{
    /// The KeySized used for this algorithm
    const KEY_SIZE: u8;

    /// The algorithm ID used in APDU packets
    const ALGORITHM_ID: u8;

    /// Implemented by specializations to check if the key is weak.
    ///
    /// Returns an error if the key is weak.
    fn check_weak_key(_key: &Key<Self>) -> Result<()> {
        Ok(())
    }
}

impl MgmKeyAlgorithm for des::TdesEde3 {
    const KEY_SIZE: u8 = 24;
    const ALGORITHM_ID: u8 = 0x03;

    /// Is this 3DES key weak?
    ///
    /// This check is performed automatically when the key is instantiated to
    /// ensure no such keys are used.
    fn check_weak_key(key: &Key<Self>) -> Result<()> {
        /// Weak and semi weak DES keys as taken from:
        /// %A D.W. Davies
        /// %A W.L. Price
        /// %T Security for Computer Networks
        /// %I John Wiley & Sons
        /// %D 1984
        const WEAK_DES_KEYS: &[[u8; DES_LEN_DES]] = &[
            // weak keys
            [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
            [0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE],
            [0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E],
            [0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1],
            // semi-weak keys
            [0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE],
            [0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01],
            [0x1F, 0xE0, 0x1F, 0xE0, 0x0E, 0xF1, 0x0E, 0xF1],
            [0xE0, 0x1F, 0xE0, 0x1F, 0xF1, 0x0E, 0xF1, 0x0E],
            [0x01, 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1],
            [0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1, 0x01],
            [0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E, 0xFE],
            [0xFE, 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E],
            [0x01, 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E],
            [0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E, 0x01],
            [0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE],
            [0xFE, 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1],
        ];

        let key_bytes = key.as_slice();

        // set odd parity of key
        let mut tmp = Zeroizing::new([0u8; Self::KEY_SIZE as usize]);

        for i in 0..(Self::KEY_SIZE as usize) {
            // count number of set bits in byte, excluding the low-order bit - SWAR method
            let mut c = key[i] & 0xFE;

            c = (c & 0x55) + ((c >> 1) & 0x55);
            c = (c & 0x33) + ((c >> 2) & 0x33);
            c = (c & 0x0F) + ((c >> 4) & 0x0F);

            // if count is even, set low key bit to 1, otherwise 0
            tmp[i] = (key[i] & 0xFE) | u8::from(c & 0x01 != 0x01);
        }

        // check odd parity key against table by DES key block
        for weak_key in WEAK_DES_KEYS.iter() {
            if weak_key == &tmp[0..DES_LEN_DES]
                || weak_key == &tmp[DES_LEN_DES..2 * DES_LEN_DES]
                || weak_key == &tmp[2 * DES_LEN_DES..3 * DES_LEN_DES]
            {
                error!(
                    "blacklisting key '{:?}' since it's weak (with odd parity)",
                    &key_bytes
                );

                return Err(Error::KeyError);
            }
        }

        Ok(())
    }
}

impl MgmKeyAlgorithm for aes::Aes128 {
    const KEY_SIZE: u8 = 16;
    const ALGORITHM_ID: u8 = 0x08;
}

impl MgmKeyAlgorithm for aes::Aes192 {
    const KEY_SIZE: u8 = 24;
    const ALGORITHM_ID: u8 = 0x0A;
}

impl MgmKeyAlgorithm for aes::Aes256 {
    const KEY_SIZE: u8 = 32;
    const ALGORITHM_ID: u8 = 0x0C;
}

/// Management Key (MGM).
///
/// This key is used to authenticate to the management applet running on
/// a YubiKey in order to perform administrative functions.
///
/// The only supported algorithm for MGM keys are 3DES and AES.
#[derive(Clone)]
pub struct MgmKey<C: MgmKeyAlgorithm> {
    key: Key<C>,
    _cipher: std::marker::PhantomData<C>,
}

/// A Management Key (MGM) using Triple-DES
pub type MgmKey3Des = MgmKey<des::TdesEde3>;

/// A Management Key (MGM) using AES-128
pub type MgmKeyAes128 = MgmKey<aes::Aes128>;

/// A Management Key (MGM) using AES-192
pub type MgmKeyAes192 = MgmKey<aes::Aes192>;

/// A Management Key (MGM) using AES-256
pub type MgmKeyAes256 = MgmKey<aes::Aes256>;

impl<C: MgmKeyAlgorithm> MgmKey<C> {
    /// Generate a random MGM key
    pub fn generate() -> Self {
        let key = C::generate_key(&mut OsRng);
        Self {
            key,
            _cipher: std::marker::PhantomData,
        }
    }

    /// Create an MGM key from byte slice.
    ///
    /// Returns an error if the slice is the wrong size or the key is weak.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() != C::key_size() {
            return Err(Error::SizeError);
        }

        let key = Key::<C>::from_slice(bytes);
        Self::new(key.clone())
    }

    /// Create an MGM key from the given key.
    ///
    /// Returns an error if the key is weak.
    pub fn new(key: Key<C>) -> Result<Self> {
        C::check_weak_key(&key)?;
        Ok(Self {
            key,
            _cipher: std::marker::PhantomData,
        })
    }

    /// Get derived management key (MGM)
    #[cfg(feature = "untested")]
    pub fn get_derived(yubikey: &mut YubiKey, pin: &[u8]) -> Result<Self> {
        let txn = yubikey.begin_transaction()?;

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

        let mut mgm = vec![0u8; C::KEY_SIZE as usize];
        pbkdf2_hmac::<Sha1>(pin, salt, ITER_MGM_PBKDF2, &mut mgm);
        MgmKey::from_bytes(mgm)
    }

    /// Get protected management key (MGM)
    #[cfg(feature = "untested")]
    pub fn get_protected(yubikey: &mut YubiKey) -> Result<Self> {
        let txn = yubikey.begin_transaction()?;

        let protected_data = ProtectedData::read(&txn).map_err(|e| {
            error!("could not read protected data (err: {:?})", e);
            e
        })?;

        let item = protected_data.get_item(TAG_PROTECTED_MGM).map_err(|e| {
            error!("could not read protected MGM from metadata (err: {:?})", e);
            e
        })?;

        if item.len() != C::KEY_SIZE as usize {
            error!(
                "protected data contains MGM, but is the wrong size: {} (expected {})",
                item.len(),
                C::KEY_SIZE
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
        Self::default().set_manual(yubikey, false)
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

        txn.set_mgm_key(self, require_touch).map_err(|e| {
            // Log a warning, since the device mgm key is corrupt or we're in a state
            // where we can't set the mgm key.
            error!("could not set new derived mgm key, err = {}", e);
            e
        })?;

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

        txn.set_mgm_key(self, false).map_err(|e| {
            // log a warning, since the device mgm key is corrupt or we're in
            // a state where we can't set the mgm key
            error!("could not set new derived mgm key, err = {}", e);
            e
        })?;

        // after this point, we've set the mgm key, so the function should
        // succeed, regardless of being able to set the metadata

        // Fetch the current protected data, or start a blank metadata blob.
        let mut protected_data = ProtectedData::read(&txn).unwrap_or_default();

        // Set the new mgm key in protected data.
        if let Err(e) = protected_data.set_item(TAG_PROTECTED_MGM, self.as_ref()) {
            error!("could not set protected mgm item, err = {:?}", e);
        } else {
            protected_data.write(&txn).map_err(|e| {
                error!("could not write protected data, err = {:?}", e);
                e
            })?;
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

    /// Return the size of the key used in management operations for a given algorithm
    pub const fn key_size(&self) -> u8 {
        C::KEY_SIZE
    }

    /// Given a challenge from a card, decrypt it and return the value
    pub(crate) fn card_challenge(&self, challenge: &[u8]) -> Result<Vec<u8>> {
        if challenge.len() != C::block_size() {
            return Err(Error::SizeError);
        }

        let mut output = challenge.to_owned();

        C::new(&self.key).decrypt_block(GenericArray::from_mut_slice(&mut output));

        Ok(output)
    }

    /// Checks the authentication matches the challenge and auth data
    pub(crate) fn check_challenge(&self, challenge: &[u8], auth_data: &[u8]) -> Result<()> {
        let mut response = challenge.to_owned();

        if challenge.len() != C::block_size() {
            return Err(Error::AuthenticationError);
        }

        C::new(&self.key).encrypt_block(GenericArray::from_mut_slice(&mut response));

        use subtle::ConstantTimeEq;
        if response.ct_eq(auth_data).unwrap_u8() != 1 {
            return Err(Error::AuthenticationError);
        }

        Ok(())
    }

    /// Return the ID used to identify the key algorithm with APDU packets
    pub(crate) fn algorithm_id(&self) -> u8 {
        C::ALGORITHM_ID
    }
}

impl<C: MgmKeyAlgorithm> AsRef<[u8]> for MgmKey<C> {
    fn as_ref(&self) -> &[u8] {
        self.key.as_ref()
    }
}

/// Default MGM key configured on all YubiKeys
impl<C: MgmKeyAlgorithm> Default for MgmKey<C> {
    fn default() -> Self {
        let key = Key::<C>::from_slice(&DEFAULT_MGM_KEY).clone();
        Self {
            key,
            _cipher: std::marker::PhantomData,
        }
    }
}

impl<C: MgmKeyAlgorithm> Drop for MgmKey<C> {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl<'a, C: MgmKeyAlgorithm> TryFrom<&'a [u8]> for MgmKey<C> {
    type Error = Error;

    fn try_from(key_bytes: &'a [u8]) -> Result<Self> {
        Self::from_bytes(key_bytes)
    }
}

// Seal the MgmKeyAlgorithm trait
mod private {
    pub trait Seal {}
    impl Seal for des::TdesEde3 {}
    impl Seal for aes::Aes128 {}
    impl Seal for aes::Aes192 {}
    impl Seal for aes::Aes256 {}
}
