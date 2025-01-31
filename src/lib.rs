#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/iqlusioninc/yubikey.rs/main/img/logo-sq.png"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

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

mod apdu;
mod cccid;
pub mod certificate;
mod chuid;
mod config;
mod consts;
mod error;
pub mod hsmauth;
mod metadata;
mod mgm;
#[cfg(feature = "untested")]
mod mscmap;
#[cfg(feature = "untested")]
mod msroots;
mod otp;
pub mod piv;
mod policy;
pub mod reader;
mod serialization;
mod setting;
mod transaction;
mod yubikey;

pub use crate::{
    cccid::{CardId, CccId},
    certificate::Certificate,
    chuid::ChuId,
    config::Config,
    error::{Error, Result},
    mgm::{MgmKey, MgmType},
    piv::Key,
    policy::{PinPolicy, TouchPolicy},
    reader::Context,
    setting::{Setting, SettingSource},
    yubikey::{CachedPin, Serial, Version, YubiKey},
};

#[cfg(feature = "untested")]
pub use crate::{mscmap::MsContainer, msroots::MsRoots};

pub use uuid::Uuid;

/// Object identifiers: handles to particular objects stored on a YubiKey.
pub type ObjectId = u32;

/// Buffer type (self-zeroizing byte vector)
pub type Buffer = zeroize::Zeroizing<Vec<u8>>;
