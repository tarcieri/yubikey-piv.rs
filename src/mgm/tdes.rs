use cipher::Key;
use zeroize::Zeroizing;

use crate::{Error, Result};

use super::{MgmAlgorithmId, MgmKeyAlgorithm, SpecificMgmKey};

/// Size of a DES key
const DES_LEN_DES: usize = 8;

/// Size of a 3DES key
const DES_LEN_3DES: usize = DES_LEN_DES * 3;

impl MgmKeyAlgorithm for des::TdesEde3 {
    const ALGORITHM_ID: MgmAlgorithmId = MgmAlgorithmId::ThreeDes;

    fn check_weak_key(key: &Key<Self>) -> Result<()> {
        if is_weak_key(key.into()) {
            Err(Error::KeyError)
        } else {
            Ok(())
        }
    }
}

/// A Management Key (MGM) using Triple-DES
pub type MgmKey3Des = SpecificMgmKey<des::TdesEde3>;

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

/// Is this 3DES key weak?
///
/// This check is performed automatically when the key is instantiated to
/// ensure no such keys are used.
fn is_weak_key(key: &[u8; DES_LEN_3DES]) -> bool {
    // set odd parity of key
    let mut tmp = Zeroizing::new([0u8; DES_LEN_3DES]);

    for i in 0..DES_LEN_3DES {
        // count number of set bits in byte, excluding the low-order bit - SWAR method
        let mut c = key[i] & 0xFE;

        c = (c & 0x55) + ((c >> 1) & 0x55);
        c = (c & 0x33) + ((c >> 2) & 0x33);
        c = (c & 0x0F) + ((c >> 4) & 0x0F);

        // if count is even, set low key bit to 1, otherwise 0
        tmp[i] = (key[i] & 0xFE) | u8::from(c & 0x01 != 0x01);
    }

    // check odd parity key against table by DES key block
    let mut is_weak = false;

    for weak_key in WEAK_DES_KEYS.iter() {
        if weak_key == &tmp[0..DES_LEN_DES]
            || weak_key == &tmp[DES_LEN_DES..2 * DES_LEN_DES]
            || weak_key == &tmp[2 * DES_LEN_DES..3 * DES_LEN_DES]
        {
            is_weak = true;
            break;
        }
    }

    is_weak
}
