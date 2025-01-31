#![allow(dead_code)]
//! Miscellaneous constant values

/// YubiKey max buffer size
pub(crate) const CB_BUF_MAX: usize = 3072;

/// YubiKey max object size
pub(crate) const CB_OBJ_MAX: usize = CB_BUF_MAX - 9;

pub(crate) const CB_OBJ_TAG_MIN: usize = 2; // 1 byte tag + 1 byte len
#[cfg(feature = "untested")]
pub(crate) const CB_OBJ_TAG_MAX: usize = CB_OBJ_TAG_MIN + 2; // 1 byte tag + 3 bytes len

// Admin tags
pub(crate) const TAG_ADMIN_FLAGS_1: u8 = 0x81;
pub(crate) const TAG_ADMIN_SALT: u8 = 0x82;
pub(crate) const TAG_ADMIN_TIMESTAMP: u8 = 0x83;

// Protected tags
pub(crate) const TAG_PROTECTED_FLAGS_1: u8 = 0x81;
pub(crate) const TAG_PROTECTED_MGM: u8 = 0x89;

// Management
pub(crate) const TAG_USB_SUPPORTED: u8 = 0x01;
pub(crate) const TAG_SERIAL: u8 = 0x02;
pub(crate) const TAG_USB_ENABLED: u8 = 0x03;
pub(crate) const TAG_FORM_FACTOR: u8 = 0x04;
pub(crate) const TAG_VERSION: u8 = 0x05;
pub(crate) const TAG_AUTO_EJECT_TIMEOUT: u8 = 0x06;
pub(crate) const TAG_CHALRESP_TIMEOUT: u8 = 0x07;
pub(crate) const TAG_DEVICE_FLAGS: u8 = 0x08;
pub(crate) const TAG_APP_VERSIONS: u8 = 0x09;
pub(crate) const TAG_CONFIG_LOCK: u8 = 0x0A;
pub(crate) const TAG_UNLOCK: u8 = 0x0B;
pub(crate) const TAG_REBOOT: u8 = 0x0C;
pub(crate) const TAG_NFC_SUPPORTED: u8 = 0x0D;
pub(crate) const TAG_NFC_ENABLED: u8 = 0x0E;
