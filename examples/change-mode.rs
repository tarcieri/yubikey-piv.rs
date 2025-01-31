#![cfg(feature = "untested")]

use yubikey::{mgm, YubiKey};

fn main() {
    let yubikey = YubiKey::open().unwrap();

    let mut mgmt = mgm::Manager::new(yubikey).unwrap();
    mgmt.enable_yubihsm().unwrap();
}
