//! Integration tests

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, trivial_casts, unused_qualifications)]

use log::trace;
use once_cell::sync::Lazy;
use rand_core::{OsRng, RngCore};
use rsa::pkcs1v15;
use sha2::{Digest, Sha256};
use signature::hazmat::PrehashVerifier;
use std::{env, str::FromStr, sync::Mutex};
use x509::RelativeDistinguishedName;
use yubikey::{
    certificate,
    certificate::{Certificate, PublicKeyInfo},
    piv::{self, AlgorithmId, Key, ManagementSlotId, RetiredSlotId, SlotId},
    Error, MgmKey, PinPolicy, Serial, TouchPolicy, YubiKey,
};

static YUBIKEY: Lazy<Mutex<YubiKey>> = Lazy::new(|| {
    // Only show logs if `RUST_LOG` is set
    if env::var("RUST_LOG").is_ok() {
        env_logger::builder().format_timestamp(None).init();
    }

    let yubikey = if let Ok(serial) = env::var("YUBIKEY_SERIAL") {
        let serial = Serial::from_str(&serial).unwrap();
        YubiKey::open_by_serial(serial).unwrap()
    } else {
        YubiKey::open().unwrap()
    };

    trace!("serial: {}", yubikey.serial());
    trace!("version: {}", yubikey.version());

    Mutex::new(yubikey)
});

//
// CCCID support
//

#[test]
#[ignore]
fn test_get_cccid() {
    let mut yubikey = match YUBIKEY.lock() {
        Ok(yubikey) => yubikey,
        Err(poison) => poison.into_inner(),
    };

    match yubikey.cccid() {
        Ok(cccid) => trace!("CCCID: {:?}", cccid),
        Err(Error::NotFound) => trace!("CCCID not found"),
        Err(err) => panic!("error getting CCCID: {:?}", err),
    }
}

//
// CHUID support
//

#[test]
#[ignore]
fn test_get_chuid() {
    let mut yubikey = match YUBIKEY.lock() {
        Ok(yubikey) => yubikey,
        Err(poison) => poison.into_inner(),
    };

    match yubikey.chuid() {
        Ok(chuid) => trace!("CHUID: {:?}", chuid),
        Err(Error::NotFound) => trace!("CHUID not found"),
        Err(err) => panic!("error getting CHUID: {:?}", err),
    }
}

//
// Device config support
//

#[test]
#[ignore]
fn test_get_config() {
    let mut yubikey = match YUBIKEY.lock() {
        Ok(yubikey) => yubikey,
        Err(poison) => poison.into_inner(),
    };
    let config_result = yubikey.config();
    assert!(config_result.is_ok());
    trace!("config: {:?}", config_result.unwrap());
}

//
// Cryptographic key support
//

#[test]
#[ignore]
fn test_list_keys() {
    let mut yubikey = match YUBIKEY.lock() {
        Ok(yubikey) => yubikey,
        Err(poison) => poison.into_inner(),
    };
    let keys_result = Key::list(&mut yubikey);
    assert!(keys_result.is_ok());
    trace!("keys: {:?}", keys_result.unwrap());
}

//
// PIN support
//

#[test]
#[ignore]
fn test_verify_pin() {
    let mut yubikey = match YUBIKEY.lock() {
        Ok(yubikey) => yubikey,
        Err(poison) => poison.into_inner(),
    };
    assert!(yubikey.verify_pin(b"000000").is_err());
    assert!(yubikey.verify_pin(b"123456").is_ok());
}

//
// Management key support
//

#[cfg(feature = "untested")]
#[test]
#[ignore]
fn test_set_mgmkey() {
    let mut yubikey = match YUBIKEY.lock() {
        Ok(yubikey) => yubikey,
        Err(poison) => poison.into_inner(),
    };

    assert!(yubikey.verify_pin(b"123456").is_ok());
    assert!(MgmKey::get_protected(&mut yubikey).is_err());
    assert!(yubikey.authenticate(MgmKey::default()).is_ok());

    // Set a protected management key.
    assert!(MgmKey::generate().set_protected(&mut yubikey).is_ok());
    let protected = MgmKey::get_protected(&mut yubikey).unwrap();
    assert!(yubikey.authenticate(MgmKey::default()).is_err());
    assert!(yubikey.authenticate(protected.clone()).is_ok());

    // Set a manual management key.
    let manual = MgmKey::generate();
    assert!(manual.set_manual(&mut yubikey, false).is_ok());
    assert!(MgmKey::get_protected(&mut yubikey).is_err());
    assert!(yubikey.authenticate(MgmKey::default()).is_err());
    assert!(yubikey.authenticate(protected.clone()).is_err());
    assert!(yubikey.authenticate(manual.clone()).is_ok());

    // Set back to the default management key.
    assert!(MgmKey::set_default(&mut yubikey).is_ok());
    assert!(MgmKey::get_protected(&mut yubikey).is_err());
    assert!(yubikey.authenticate(protected).is_err());
    assert!(yubikey.authenticate(manual).is_err());
    assert!(yubikey.authenticate(MgmKey::default()).is_ok());
}

//
// Certificate support
//

fn generate_self_signed_cert(algorithm: AlgorithmId) -> Certificate {
    let mut yubikey = match YUBIKEY.lock() {
        Ok(yubikey) => yubikey,
        Err(poison) => poison.into_inner(),
    };

    assert!(yubikey.verify_pin(b"123456").is_ok());
    assert!(yubikey.authenticate(MgmKey::default()).is_ok());

    let slot = SlotId::Retired(RetiredSlotId::R1);

    // Generate a new key in the selected slot.
    let generated = piv::generate(
        &mut yubikey,
        slot,
        algorithm,
        PinPolicy::Default,
        TouchPolicy::Default,
    )
    .unwrap();

    let mut serial = [0u8; 20];
    OsRng.fill_bytes(&mut serial);

    // Generate a self-signed certificate for the new key.
    let extensions: &[x509::Extension<'_, &[u64]>] = &[];
    let cert_result = Certificate::generate_self_signed(
        &mut yubikey,
        slot,
        serial,
        None,
        &[RelativeDistinguishedName::common_name("testSubject")],
        generated,
        extensions,
    );

    assert!(cert_result.is_ok());
    let cert = cert_result.unwrap();
    trace!("cert: {:?}", cert);
    cert
}

#[test]
#[ignore]
fn generate_self_signed_rsa_cert() {
    let cert = generate_self_signed_cert(AlgorithmId::Rsa1024);

    //
    // Verify that the certificate is signed correctly
    //

    let pubkey = match cert.subject_pki() {
        PublicKeyInfo::Rsa { pubkey, .. } => pkcs1v15::VerifyingKey::<Sha256>::from(pubkey.clone()),
        _ => unreachable!(),
    };

    let data = cert.as_ref();
    let tbs_cert_len = u16::from_be_bytes(data[6..8].try_into().unwrap()) as usize;
    let msg = &data[4..8 + tbs_cert_len];
    let sig = pkcs1v15::Signature::try_from(&data[data.len() - 128..]).unwrap();
    let hash = Sha256::digest(msg);

    assert!(pubkey.verify_prehash(&hash, &sig).is_ok());
}

#[test]
#[ignore]
fn generate_self_signed_ec_cert() {
    let cert = generate_self_signed_cert(AlgorithmId::EccP256);

    //
    // Verify that the certificate is signed correctly
    //

    let pubkey = match cert.subject_pki() {
        PublicKeyInfo::EcP256(pubkey) => pubkey,
        _ => unreachable!(),
    };

    let data = cert.as_ref();
    let tbs_cert_len = data[6] as usize;
    let sig_algo_len = data[7 + tbs_cert_len + 1] as usize;
    let sig_start = 7 + tbs_cert_len + 2 + sig_algo_len + 3;
    let msg = &data[4..7 + tbs_cert_len];
    let sig = p256::ecdsa::Signature::from_der(&data[sig_start..]).unwrap();
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(pubkey.as_bytes()).unwrap();

    use p256::ecdsa::signature::Verifier;
    assert!(vk.verify(msg, &sig).is_ok());
}

#[test]
#[ignore]
fn generate_self_signed_cv_cert() {
    let cert = generate_self_signed_cert(AlgorithmId::Ed25519);

    //
    // Verify that the certificate is signed correctly
    //

    let pubkey = match cert.subject_pki() {
        PublicKeyInfo::Ed25519(pubkey) => pubkey,
        _ => unreachable!(),
    };

    let data = cert.as_ref();
    let cert_len = data[2] as usize;
    let tbs_cert_len = data[5] as usize;
    let sig_algo_len: usize = 64;
    let sig_start = cert_len - sig_algo_len + 3;
    let msg = &data[3..6 + tbs_cert_len];
    let sig =
        ed25519_dalek::Signature::from_slice(&data[sig_start..sig_start + sig_algo_len]).unwrap();

    use ed25519_dalek::Verifier;
    assert!(pubkey.verify(msg, &sig).is_ok());
}

#[test]
#[ignore]
fn test_slot_id_display() {
    assert_eq!(format!("{}", SlotId::Authentication), "Authentication");
    assert_eq!(format!("{}", SlotId::Signature), "Signature");
    assert_eq!(format!("{}", SlotId::KeyManagement), "KeyManagement");
    assert_eq!(
        format!("{}", SlotId::CardAuthentication),
        "CardAuthentication"
    );
    assert_eq!(format!("{}", SlotId::Attestation), "Attestation");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R1)), "R1");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R2)), "R2");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R3)), "R3");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R4)), "R4");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R5)), "R5");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R6)), "R6");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R7)), "R7");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R8)), "R8");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R9)), "R9");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R10)), "R10");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R11)), "R11");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R12)), "R12");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R13)), "R13");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R14)), "R14");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R15)), "R15");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R16)), "R16");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R17)), "R17");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R18)), "R18");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R19)), "R19");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R20)), "R20");

    assert_eq!(
        format!("{}", SlotId::Management(ManagementSlotId::Pin)),
        "Pin"
    );
    assert_eq!(
        format!("{}", SlotId::Management(ManagementSlotId::Puk)),
        "Puk"
    );
    assert_eq!(
        format!("{}", SlotId::Management(ManagementSlotId::Management)),
        "Management"
    );
}

//
// Metadata
//

#[test]
#[ignore]
fn test_read_metadata() {
    let mut yubikey = match YUBIKEY.lock() {
        Ok(yubikey) => yubikey,
        Err(poison) => poison.into_inner(),
    };

    assert!(yubikey.verify_pin(b"123456").is_ok());
    assert!(yubikey.authenticate(MgmKey::default()).is_ok());

    let slot = SlotId::Retired(RetiredSlotId::R1);

    // Generate a new key in the selected slot.
    let generated = piv::generate(
        &mut yubikey,
        slot,
        AlgorithmId::EccP256,
        PinPolicy::Default,
        TouchPolicy::Default,
    )
    .unwrap();

    let metadata = piv::metadata(&mut yubikey, slot).unwrap();

    assert_eq!(metadata.public, Some(generated));
}

#[test]
#[ignore]
fn test_serial_string_conversions() {
    //2^152+1
    let serial: [u8; 20] = [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    let s = certificate::Serial::from(serial);
    assert_eq!(
        s.as_x509_int(),
        "5708990770823839524233143877797980545530986497"
    );
    assert_eq!(
        s.as_x509_hex(),
        "01:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01"
    );

    let serial2: [u8; 20] = [
        0xA1, 0xF3, 0x02, 0x30, 0x76, 0x01, 0x32, 0x48, 0x09, 0x9C, 0x10, 0xAA, 0x3F, 0xA0, 0x54,
        0x0D, 0xC0, 0xB7, 0x65, 0x01,
    ];

    let s2 = certificate::Serial::from(serial2);
    assert_eq!(
        s2.as_x509_int(),
        "924566785900861696177829411010986812227211191553"
    );
    assert_eq!(
        s2.as_x509_hex(),
        "a1:f3:02:30:76:01:32:48:09:9c:10:aa:3f:a0:54:0d:c0:b7:65:01"
    );

    let serial3: [u8; 20] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0x3F, 0xA0, 0x54,
        0x0D, 0xC0, 0xB7, 0x65, 0x01,
    ];

    let s3 = certificate::Serial::from(serial3);
    assert_eq!(s3.as_x509_int(), "3140531249369331492097");
    assert_eq!(s3.as_x509_hex(), "aa:3f:a0:54:0d:c0:b7:65:01");
}

#[test]
#[ignore]
fn test_parse_cert_from_der() {
    let bob_der = std::fs::read("tests/assets/Bob.der").expect(".der file not found");
    let cert =
        certificate::Certificate::from_bytes(bob_der).expect("Failed to parse valid certificate");
    assert_eq!(
        cert.subject(),
        "CN=Bob",
        "Subject is {} should be CN=Bob",
        cert.subject()
    );
    assert_eq!(
        cert.issuer(),
        "CN=Ferdinand Linnenberg CA",
        "Issuer is {} should be {}",
        cert.issuer(),
        "CN=Ferdinand Linnenberg CA"
    );
}
