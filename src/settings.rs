//! Configuration setting values parsed from the environment and config file:
//! `/etc/yubico/yubikeypiv.conf`

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

/// Default location of the YubiKey PIV configuration file
pub const DEFAULT_CONFIG_FILE: &str = "/etc/yubico/yubikeypiv.conf";

use std::{
    env,
    fs::File,
    io::{BufRead, BufReader},
};

/// Source of how a setting was configured
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    /// User-specified setting
    User,

    /// Admin-specified setting
    Admin,

    /// Default setting
    Default,
}

impl Default for Source {
    fn default() -> Self {
        Self::Default
    }
}

/// Setting booleans
#[derive(Copy, Clone, Debug)]
pub struct ConfigValue {
    /// Boolean value
    pub value: bool,

    /// Source of the configuration setting (user, admin, or default)
    pub source: Source,
}

impl ConfigValue {
    /// Get a [`BoolValue`] value by name.
    pub fn get(key: &str, default: bool) -> Self {
        Self::from_file(key)
            .or_else(|| Self::from_env(key))
            .unwrap_or(Self {
                value: default,
                source: Source::Default,
            })
    }

    /// Get a boolean config value from the provided config file
    fn from_file(key: &str) -> Option<Self> {
        if let Ok(file) = File::open(DEFAULT_CONFIG_FILE) {
            for line in BufReader::new(file).lines() {
                let line = match line {
                    Ok(line) => line,
                    _ => continue,
                };

                if line.starts_with('#') || line.starts_with('\r') || line.starts_with('\n') {
                    continue;
                }

                let (name, value) = {
                    let mut parts = line.splitn(1, '=');
                    let name = parts.next();
                    let value = parts.next();
                    match (name, value, parts.next()) {
                        (Some(name), Some(value), None) => (name.trim(), value.trim()),
                        _ => continue,
                    }
                };

                if name == key {
                    return Some(ConfigValue {
                        source: Source::Admin,
                        value: value == "1" || value == "true",
                    });
                }
            }
        }

        None
    }

    /// Get a setting boolean from an environment variable
    fn from_env(key: &str) -> Option<Self> {
        env::var(format!("YUBIKEY_PIV_{}", key))
            .ok()
            .map(|value| ConfigValue {
                source: Source::User,
                value: value == "1" || value == "true",
            })
    }
}

impl Default for ConfigValue {
    fn default() -> Self {
        Self {
            value: false,
            source: Source::default(),
        }
    }
}
