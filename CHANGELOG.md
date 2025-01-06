# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- `yubikey::certificate::SelfSigned`
- `yubikey::Error::CertificateBuilder`
- `yubikey::MgmAlgorithmId`

### Changed
- MSRV is now 1.81.
- Migrated the public API to the following (pre-release) dependencies:
  - `der 0.8.0-rc.1`
  - `ecdsa 0.17.0-pre.9`
  - `p256 0.14.0-pre.2`
  - `p384 0.14.0-pre.2`
  - `rsa 0.10.0-pre.3`
  - `sha2 0.11.0-pre.4`
  - `x509-cert 0.3.0-pre.0`
- `yubikey::piv`:
  - `ManagementAlgorithmId` has been renamed to `SlotAlgorithmId`, and its
    `ThreeDes` variant has been replaced by `SlotAlgorithmId::Management`
    containing a `yubikey::MgmAlgorithmId`.

## 0.8.0 (2023-08-15)
### Added
- `impl Debug for {Context, YubiKey}` ([#457])
- `YubiKey::disconnect` ([#462])
- `Error::AppletNotFound` ([#476])

### Changed
- `Reader::open` now returns `Error::AppletNotFound` instead of `Error::Generic`
  if the PIV applet is not present on the device. This is returned by non-PIV
  virtual smart cards like Windows Hello for Business, as well as some smart
  card readers when no card is present.
- `Reader::open` now avoids resetting the card if an error occurs (equivalent to
  calling `YubiKey::disconnect(pcsc::Disposition::LeaveCard)` if `Reader::open`
  succeeds).
- Raise minimum `pcsc` version to 2.3.1 and remove workaround ([#478])
- Bump asymmetric crypto dependencies; MSRV 1.65 ([#490])
  - `elliptic-curve` v0.13
  - `k256` v0.13
  - `p256` v0.13
  - `p384` v0.13
  - `pbkdf2` v0.12
  - `rsa` v0.9 ([#502])
  - `signature` v2
- Use `x509-cert` certificate builder ([#495])
- Make `RsaKeyData::new` fallible ([#517])

### Fixed
- `StatusWords::code` now returns the correct code (including embedded `tries`
  count) for `StatusWords::VerifyFailError`. Previously the returned code lost
  information and was not round-trip compatible with `StatusWords::from(u16)`.
- Parsing of serial numbers ([#466])
- Make `YubiKey::open()` more robust ([#504])

[#457]: https://github.com/iqlusioninc/yubikey.rs/pull/457
[#462]: https://github.com/iqlusioninc/yubikey.rs/pull/462
[#466]: https://github.com/iqlusioninc/yubikey.rs/pull/466
[#476]: https://github.com/iqlusioninc/yubikey.rs/pull/476
[#478]: https://github.com/iqlusioninc/yubikey.rs/pull/478
[#490]: https://github.com/iqlusioninc/yubikey.rs/pull/490
[#495]: https://github.com/iqlusioninc/yubikey.rs/pull/495
[#502]: https://github.com/iqlusioninc/yubikey.rs/pull/502
[#504]: https://github.com/iqlusioninc/yubikey.rs/pull/504
[#517]: https://github.com/iqlusioninc/yubikey.rs/pull/517

## 0.7.0 (2022-11-14)
### Added
- Display inner PC/SC errors ([#420])
- Support for metadata command ([#371])
- Better `certificate::Serial` inspection ([#437])

### Changed
- MSRV 1.60.0 ([#423])
- Bump `rsa` to v0.7.1 ([#440])
- Switch from `lazy_static` to `once_cell` ([#442])
- Switch from `subtle-encoding` to `base16ct` ([#443])

### Fixed
- Use `chrono` v0.4.23 or newer ([#436])
- `Certificate::issuer` was returning the subject instead ([#437])

[#371]: https://github.com/iqlusioninc/yubikey.rs/pull/371
[#420]: https://github.com/iqlusioninc/yubikey.rs/pull/420
[#423]: https://github.com/iqlusioninc/yubikey.rs/pull/423
[#436]: https://github.com/iqlusioninc/yubikey.rs/pull/436
[#437]: https://github.com/iqlusioninc/yubikey.rs/pull/437
[#440]: https://github.com/iqlusioninc/yubikey.rs/pull/440
[#442]: https://github.com/iqlusioninc/yubikey.rs/pull/442
[#443]: https://github.com/iqlusioninc/yubikey.rs/pull/443

## 0.6.0 (2022-08-10)
### Changed
- 2021 edition upgrade ([#343])
- RustCrypto crate upgrades; MSRV 1.57 ([#378])
  - `des` v0.8
  - `elliptic-curve` v0.12
  - `hmac` v0.12
  - `num-bigint-dig` v0.8
  - `pbkdf2` v0.11
  - `p256` v0.11
  - `p384` v0.11
  - `rsa` v0.6
  - `sha1` v0.10 (replacing `sha-1`)
  - `sha2` v0.10
- Bump `uuid` to v1.0 ([#376])
- Bump `der-parser` to v8.0 ([#402])
- Bump `x509-parser` to v0.14 ([#402])

[#343]: https://github.com/iqlusioninc/yubikey.rs/pull/343
[#376]: https://github.com/iqlusioninc/yubikey.rs/pull/376
[#378]: https://github.com/iqlusioninc/yubikey.rs/pull/378
[#402]: https://github.com/iqlusioninc/yubikey.rs/pull/402

## 0.5.0 (2021-11-21)
### Changed
- Update `rsa` dependency to 0.5 ([#315])
- Update `pbkdf2` dependency to 0.9 ([#315])
- Update `x509-parser` dependency to 0.12 ([#315], [#322])
- Update `nom` to v7.0 ([#322])

[#315]: https://github.com/iqlusioninc/yubikey.rs/pull/315
[#322]: https://github.com/iqlusioninc/yubikey.rs/pull/322

## 0.4.2 (2021-07-13)
### Added
- Make `yubikey::Buffer` a pub type ([#290])

### Changed
- Have `YubiKey::block_puk` take `&mut self` as argument ([#289])

[#289]: https://github.com/iqlusioninc/yubikey.rs/pull/289
[#290]: https://github.com/iqlusioninc/yubikey.rs/pull/290

## 0.4.1 (2021-07-12)
### Changed
- Rename `SettingValue` to `Setting` ([#286])
- Rename `Ccc` to `CccId` ([#287])

[#286]: https://github.com/iqlusioninc/yubikey.rs/pull/286
[#287]: https://github.com/iqlusioninc/yubikey.rs/pull/287

## 0.4.0 (2021-07-12) [YANKED]
### Added
- `Result` alias ([#271])

### Changed
- Renamed crate from `yubikey-piv` => `yubikey` ([#267])
- Renamed the following:
    - `APDU` => `Apdu` ([#269])
    - `CCC` => `Ccc` ([#269])
    - `CHUID` => `ChuId` ([#269])
    - `Ccc::cccid` => `Ccc::card_id` ([#270])
    - `key` => `piv` ([#277])
    - `readers` => `reader` ([#278])
    - `readers::Readers` => `reader::Context` ([#278])
- Bumped the following dependencies:
  - `rsa` => v0.4 ([#246])
  - `des` => v0.7 ([#251])
  - `elliptic-curve` => v0.10 ([#268])
  - `hmac` => v0.11 ([#251])
  - `pbkdf2` => v0.8 ([#251])
  - `p256` => v0.9 ([#268])
  - `p384` => v0.8 ([#268])
- MSRV 1.51+ ([#268])
- Flatten API ([#274])
- Replace `getrandom` with `rand_core` ([#276])

### Fixed
- Potential local DoS in TLV parser ([#279])

[#246]: https://github.com/iqlusioninc/yubikey.rs/pull/246
[#251]: https://github.com/iqlusioninc/yubikey.rs/pull/251
[#267]: https://github.com/iqlusioninc/yubikey.rs/pull/267
[#268]: https://github.com/iqlusioninc/yubikey.rs/pull/268
[#269]: https://github.com/iqlusioninc/yubikey.rs/pull/269
[#270]: https://github.com/iqlusioninc/yubikey.rs/pull/270
[#271]: https://github.com/iqlusioninc/yubikey.rs/pull/271
[#274]: https://github.com/iqlusioninc/yubikey.rs/pull/274
[#276]: https://github.com/iqlusioninc/yubikey.rs/pull/276
[#277]: https://github.com/iqlusioninc/yubikey.rs/pull/277
[#278]: https://github.com/iqlusioninc/yubikey.rs/pull/278
[#279]: https://github.com/iqlusioninc/yubikey.rs/pull/279

## yubikey-piv 0.3.0 (2021-03-22)
### Added
- Typed structs for PIN-protected and admin metadata ([#223])
- `MgmKey::set_default`/`MgmKey::set_manual` methods ([#224])

### Changed
- Have `Transaction::set_mgm_key` take touch requirement as bool ([#224])

### Removed
- `MgmKey::set` method ([#224])

[#223]: https://github.com/iqlusioninc/yubikey.rs/pull/223
[#224]: https://github.com/iqlusioninc/yubikey.rs/pull/224

## yubikey-piv 0.2.0 (2021-01-30)
### Changed
- Bump `der-parser` to v5.0 ([#194])
- Improve self-signed certificates ([#207])
- Bump `x509-parser` to v0.9 ([#208])
- Bump elliptic-curve to 0.8. Also requires bumping p256 and p384 ([#208])
- Bump MSRV to 1.46+ ([#208])
- Bump `pbkdf2` dependency to v0.7 ([#219])

[#194]: https://github.com/iqlusioninc/yubikey.rs/pull/194
[#207]: https://github.com/iqlusioninc/yubikey.rs/pull/207
[#208]: https://github.com/iqlusioninc/yubikey.rs/pull/208
[#219]: https://github.com/iqlusioninc/yubikey.rs/pull/219

## yubikey-piv 0.1.0 (2020-10-19)
### Added
- `Certificate::generate_self_signed` ([#80])
- `YubiKey::open_by_serial` ([#69])
- CCCID/CHUID tests and cleanups ([#65])
- Test `Config::get` ([#64])
- Test `Key::list` ([#61])
- Test `YubiKey::verify_pin` ([#60])

### Changed
- Bump `crypto-mac`, `des`, `hmac`, `pbkdf2` ([#177])
- Bump `p256` to v0.5; `p384` to v0.4; MSRV 1.44+ ([#175])
- Refactor key import function ([#128])
- Extract `ChangeRefAction` enum ([#82])
- TLV extraction ([#73])
- Rename `container` to `mscmap` ([#68])
- Finish eliminating `consts` module ([#67])
- Move `sign`/`decrypt`/`import`/`attest` to the `key` module ([#62])

### Fixed
- `pcsc::Error::NoReadersAvailable` -> `Error::NotFound` in `YubiKey::open*` ([#88])

### Removed
- YubiKey NEO support ([#63])

[#177]: https://github.com/iqlusioninc/yubikey.rs/pull/177
[#175]: https://github.com/iqlusioninc/yubikey.rs/pull/175
[#128]: https://github.com/iqlusioninc/yubikey.rs/pull/128
[#82]: https://github.com/iqlusioninc/yubikey.rs/pull/82
[#73]: https://github.com/iqlusioninc/yubikey.rs/pull/73
[#88]: https://github.com/iqlusioninc/yubikey.rs/pull/88
[#80]: https://github.com/iqlusioninc/yubikey.rs/pull/80
[#69]: https://github.com/iqlusioninc/yubikey.rs/pull/69
[#68]: https://github.com/iqlusioninc/yubikey.rs/pull/68
[#67]: https://github.com/iqlusioninc/yubikey.rs/pull/67
[#65]: https://github.com/iqlusioninc/yubikey.rs/pull/65
[#64]: https://github.com/iqlusioninc/yubikey.rs/pull/64
[#63]: https://github.com/iqlusioninc/yubikey.rs/pull/63
[#62]: https://github.com/iqlusioninc/yubikey.rs/pull/62
[#61]: https://github.com/iqlusioninc/yubikey.rs/pull/61
[#60]: https://github.com/iqlusioninc/yubikey.rs/pull/60

## yubikey-piv 0.0.3 (2019-12-02)
### Added
- Initial `Readers` enumerator for detecting YubiKeys ([#51])
- Certificate parsing ([#45])

### Changed
- Use `Reader` to connect to `YubiKey` ([#51])
- Convert `SlotId` and `AlgorithmId` into enums ([#44])
- Use `secrecy` crate for storing `CachedPin` ([#43])
- Change `CHUID` struct to hold complete CHUID value ([#42])
- Eliminate all usages of `unsafe` ([#37], [#39])
- Make anonymous CHUID struct public ([#36])
- Have `sign_data` and `decrypt_data` return a `Buffer` ([#34])
- `Ins` (APDU instruction codes) enum ([#33])
- Factor `Response` into `apdu` module; improved debugging ([#32])

[#51]: https://github.com/iqlusioninc/yubikey.rs/pull/51
[#45]: https://github.com/iqlusioninc/yubikey.rs/pull/45
[#44]: https://github.com/iqlusioninc/yubikey.rs/pull/44
[#43]: https://github.com/iqlusioninc/yubikey.rs/pull/43
[#42]: https://github.com/iqlusioninc/yubikey.rs/pull/42
[#39]: https://github.com/iqlusioninc/yubikey.rs/pull/39
[#37]: https://github.com/iqlusioninc/yubikey.rs/pull/37
[#36]: https://github.com/iqlusioninc/yubikey.rs/pull/36
[#34]: https://github.com/iqlusioninc/yubikey.rs/pull/34
[#33]: https://github.com/iqlusioninc/yubikey.rs/pull/33
[#32]: https://github.com/iqlusioninc/yubikey.rs/pull/32

## yubikey-piv 0.0.2 (2019-11-25)
### Added
- `untested` Cargo feature to mark untested functionality ([#30])
- Initial connect test and docs ([#19])
- Clean up APDU construction with builder API ([#15])

### Changed
- Rewrite translated code to use the `pcsc` crate ([#17])
- Rename ErrorKind to Error ([#13])
- Use `des` crate for 3DES operations ([#10])
- Replace `PKCS5_PBKDF2_HMAC_SHA1` with `pbkdf2` et al crates ([#9])
- Replace `RAND_bytes` with `getrandom` crate ([#8])
- Use `log` crate for logging ([#7])
- Replace `ErrorKind::Ok` with `Result` ([#6])

[#30]: https://github.com/iqlusioninc/yubikey.rs/pull/30
[#19]: https://github.com/iqlusioninc/yubikey.rs/pull/19
[#17]: https://github.com/iqlusioninc/yubikey.rs/pull/17
[#15]: https://github.com/iqlusioninc/yubikey.rs/pull/15
[#13]: https://github.com/iqlusioninc/yubikey.rs/pull/13
[#10]: https://github.com/iqlusioninc/yubikey.rs/pull/10
[#9]: https://github.com/iqlusioninc/yubikey.rs/pull/9
[#8]: https://github.com/iqlusioninc/yubikey.rs/pull/8
[#7]: https://github.com/iqlusioninc/yubikey.rs/pull/7
[#6]: https://github.com/iqlusioninc/yubikey.rs/pull/6

## yubikey-piv 0.0.1 (2019-11-18)
- Initial release
