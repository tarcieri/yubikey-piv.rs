use super::{MgmAlgorithmId, MgmKeyAlgorithm, SpecificMgmKey};

impl MgmKeyAlgorithm for aes::Aes128 {
    const ALGORITHM_ID: MgmAlgorithmId = MgmAlgorithmId::Aes128;
}

impl MgmKeyAlgorithm for aes::Aes192 {
    const ALGORITHM_ID: MgmAlgorithmId = MgmAlgorithmId::Aes192;
}

impl MgmKeyAlgorithm for aes::Aes256 {
    const ALGORITHM_ID: MgmAlgorithmId = MgmAlgorithmId::Aes256;
}

/// A Management Key (MGM) using AES-128
pub type MgmKeyAes128 = SpecificMgmKey<aes::Aes128>;

/// A Management Key (MGM) using AES-192
pub type MgmKeyAes192 = SpecificMgmKey<aes::Aes192>;

/// A Management Key (MGM) using AES-256
pub type MgmKeyAes256 = SpecificMgmKey<aes::Aes256>;
