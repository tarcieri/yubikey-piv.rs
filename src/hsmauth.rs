//! YubiHSM Auth protocol
//!
//! YubiHSM Auth is a YubiKey CCID application that stores the long-lived
//! credentials used to establish secure sessions with a YubiHSM 2. The secure
//! session protocol is based on Secure Channel Protocol 3 (SCP03).
use crate::{
    error::{Error, Result},
    transaction::Transaction,
    YubiKey,
};
use nom::{
    bytes::complete::{tag, take},
    combinator::eof,
    error::{Error as NumError, ErrorKind},
    multi::many0,
    number::complete::u8,
    IResult,
};
use std::{fmt, str::FromStr};
use zeroize::Zeroizing;

/// Yubikey HSM Auth Applet ID
pub(crate) const APPLET_ID: &[u8] = &[0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07, 0x01];
/// Yubikey HSM Auth Applet Name
pub(crate) const APPLET_NAME: &str = "YubiHSM";

/// AES key size in bytes. SCP03 theoretically supports other key sizes, but
/// the YubiHSM 2 does not. Since this crate is somewhat specialized to the `YubiHSM 2` (at least for now)
/// we hardcode to 128-bit for simplicity.
pub(crate) const KEY_SIZE: usize = 16;

/// Password to authenticate to the Yubikey HSM Auth Applet has a max length of 16
pub(crate) const PW_LEN: usize = 16;

/// Management key used to manipulate secrets (add/delete)
pub struct MgmKey(pub [u8; PW_LEN]);

impl Default for MgmKey {
    fn default() -> Self {
        // https://docs.yubico.com/yesdk/users-manual/application-yubihsm-auth/commands/change-management-key.html
        // The default value of the management key is all zeros:
        // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        Self([0; PW_LEN])
    }
}

/// Label associated with a secret on the Yubikey.
#[derive(Clone)]
pub struct Label(pub(crate) Vec<u8>);

impl FromStr for Label {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        let buf = input.as_bytes();

        if (1..=64).contains(&buf.len()) {
            Ok(Self(buf.to_vec()))
        } else {
            Err(Error::ParseError)
        }
    }
}

/// [`Context`] holds the various challenges used for the authentication.
///
/// This is used as part of the key derivation for the session keys.
pub struct Context(pub(crate) [u8; 16]);

impl Context {
    /// Creates a [`Context`] from its components
    pub fn new(host_challenge: &Challenge, hsm_challenge: &Challenge) -> Self {
        let mut out = Self::zeroed();
        out.0[..8].copy_from_slice(host_challenge.as_slice());
        out.0[8..].copy_from_slice(hsm_challenge.as_slice());

        out
    }

    fn zeroed() -> Self {
        Self([0u8; 16])
    }

    /// Build `Context` from the provided buffer
    pub fn from_buf(buf: [u8; 16]) -> Self {
        Self(buf)
    }
}

/// Exclusive access to the Hsmauth applet.
pub struct HsmAuth {
    client: YubiKey,
}

impl HsmAuth {
    pub(crate) fn new(mut client: YubiKey) -> Result<Self> {
        Transaction::new(&mut client.card)?.select_application(
            APPLET_ID,
            APPLET_NAME,
            "failed selecting YkHSM auth application",
        )?;

        Ok(Self { client })
    }

    /// Calculate session key with the specified key.
    pub fn calculate(
        &mut self,
        label: Label,
        context: Context,
        password: &[u8],
    ) -> Result<SessionKeys> {
        Transaction::new(&mut self.client.card)?.calculate(
            self.client.version,
            label,
            context,
            password,
        )
    }

    /// Get YubiKey Challenge
    pub fn get_challenge(&mut self, label: Label) -> Result<Challenge> {
        Transaction::new(&mut self.client.card)?.get_host_challenge(self.client.version, label)
    }

    /// List credentials
    pub fn list_credentials(&mut self) -> Result<Vec<Credential>> {
        Transaction::new(&mut self.client.card)?.list_credentials(self.client.version)
    }

    /// Put credential
    pub fn put_credential(
        &mut self,
        mgmkey: Option<MgmKey>,
        label: Label,
        password: &[u8],
        enc_key: [u8; KEY_SIZE],
        mac_key: [u8; KEY_SIZE],
        touch: bool,
    ) -> Result<()> {
        Transaction::new(&mut self.client.card)?.put_credential(
            self.client.version,
            mgmkey.unwrap_or_default(),
            label,
            password,
            enc_key,
            mac_key,
            touch,
        )
    }

    /// Delete credential
    pub fn delete_credential(&mut self, mgmkey: Option<MgmKey>, label: Label) -> Result<()> {
        Transaction::new(&mut self.client.card)?.delete_credential(
            self.client.version,
            mgmkey.unwrap_or_default(),
            label,
        )
    }

    /// Retun the inner `YubiKey`
    pub fn into_inner(mut self) -> Result<YubiKey> {
        Transaction::new(&mut self.client.card)?.select_piv_application()?;
        Ok(self.client)
    }
}

#[derive(Debug)]
#[repr(u8)]
/// Algorithm for the credentials
pub enum Algorithm {
    /// AES 128 keys
    Aes128 = 38,
    /// EC P256
    EcP256 = 39,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Algorithm::Aes128 => write!(f, "AES128"),
            Algorithm::EcP256 => write!(f, "ECP256"),
        }
    }
}

impl Algorithm {
    fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, value) = u8(input)?;
        match value {
            38 => Ok((input, Algorithm::Aes128)),
            39 => Ok((input, Algorithm::EcP256)),
            _ => Err(nom::Err::Error(NumError::new(input, ErrorKind::Tag))),
        }
    }
}

/// YubiHSM Auth credential store in the Application
#[derive(Debug)]
pub struct Credential {
    /// Algorithm of the key
    pub algorithm: Algorithm,
    /// Is touch required when using this credential
    pub touch: bool,
    /// Remaining attempts to authenticate to this credential
    pub remaining_attempts: u8,
    /// Label for the credential
    pub label: Vec<u8>,
}

impl Credential {
    /// Parse a buffer holding a single credential
    fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _list) = tag(b"\x72")(input)?;

        let (input, buf_len) = u8(input)?;
        let buf_len = if buf_len < 3 {
            return Err(nom::Err::Error(NumError::new(
                input,
                ErrorKind::LengthValue,
            )));
        } else {
            (buf_len - 3) as usize
        };

        let (input, algorithm) = Algorithm::parse(input)?;

        let (input, touch) = u8(input)?;
        let touch = match touch {
            0 => false,
            1 => true,
            _ => return Err(nom::Err::Error(NumError::new(input, ErrorKind::Tag))),
        };

        let (input, label) = take(buf_len)(input)?;

        let (input, remaining_attempts) = u8(input)?;

        Ok((
            input,
            Credential {
                algorithm,
                touch,
                label: label.to_vec(),
                remaining_attempts,
            },
        ))
    }

    /// Parse a buffer holding a list of `Credential`
    pub fn parse_list(input: &[u8]) -> Result<Vec<Self>> {
        let (input, credentials) =
            many0(Credential::parse)(input).map_err(|_| Error::ParseError)?;
        let (_input, _) = eof(input).map_err(|_: nom::Err<NumError<&[u8]>>| Error::ParseError)?;

        Ok(credentials)
    }
}

/// The sessions keys after negociation via SCP03.
#[derive(Default, Debug)]
pub struct SessionKeys {
    /// Session encryption key (S-ENC)
    pub enc_key: Zeroizing<[u8; KEY_SIZE]>,
    /// Session Command MAC key (S-MAC)
    pub mac_key: Zeroizing<[u8; KEY_SIZE]>,
    /// Session Respose MAC key (S-RMAC)
    pub rmac_key: Zeroizing<[u8; KEY_SIZE]>,
}

/// Host challenge used for session keys calculation
#[derive(Debug, Clone)]
pub struct Challenge {
    buffer: Zeroizing<[u8; Self::SIZE]>,
    length: usize,
}

impl Challenge {
    /// Challenge used in SCP03 computation
    /// Can be as long as a P256 PUBKEY (for SCP11 support).
    pub(crate) const SIZE: usize = 65;

    /// Returns a slice containing the entire array.
    pub fn as_slice(&self) -> &[u8] {
        &self.buffer.as_slice()[..self.length]
    }

    /// Returns true if the challenge has a length of 0.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Copy data from provided slice
    pub fn copy_from_slice(&mut self, data: &[u8]) -> Result<()> {
        self.length = data.len();
        if self.length > Self::SIZE {
            Err(Error::SizeError)
        } else {
            self.buffer[..self.length].copy_from_slice(data);
            Ok(())
        }
    }
}

impl Default for Challenge {
    fn default() -> Self {
        Self {
            buffer: Zeroizing::new([0u8; Self::SIZE]),
            length: 0,
        }
    }
}
