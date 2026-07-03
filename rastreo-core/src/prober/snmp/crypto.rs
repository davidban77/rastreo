use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut};
use digest::{Digest, Mac};
use hmac::Hmac;
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};

use super::usm::{AuthAlgo, PrivAlgo};

const PASSWORD_EXPANSION_BYTES: usize = 1_048_576;

/// Password-to-key localization per RFC 3414 §2.6.
pub fn localize_key(password: &str, engine_id: &[u8], algo: AuthAlgo) -> Vec<u8> {
    match algo {
        AuthAlgo::Md5 => localize::<Md5>(password, engine_id),
        AuthAlgo::Sha1 => localize::<Sha1>(password, engine_id),
        AuthAlgo::Sha224 => localize::<Sha224>(password, engine_id),
        AuthAlgo::Sha256 => localize::<Sha256>(password, engine_id),
        AuthAlgo::Sha384 => localize::<Sha384>(password, engine_id),
        AuthAlgo::Sha512 => localize::<Sha512>(password, engine_id),
    }
}

fn localize<D: Digest>(password: &str, engine_id: &[u8]) -> Vec<u8> {
    let pw = password.as_bytes();
    if pw.is_empty() {
        let empty = D::new().finalize();
        let mut d2 = D::new();
        d2.update(&empty);
        d2.update(engine_id);
        d2.update(&empty);
        return d2.finalize().to_vec();
    }

    let mut hasher = D::new();
    let mut fed: usize = 0;
    let mut idx: usize = 0;
    let mut chunk = [0u8; 64];
    while fed < PASSWORD_EXPANSION_BYTES {
        let take = 64.min(PASSWORD_EXPANSION_BYTES - fed);
        for slot in chunk.iter_mut().take(take) {
            *slot = pw[idx];
            idx = (idx + 1) % pw.len();
        }
        hasher.update(&chunk[..take]);
        fed += take;
    }
    let digest = hasher.finalize();

    let mut hasher2 = D::new();
    hasher2.update(&digest);
    hasher2.update(engine_id);
    hasher2.update(&digest);
    hasher2.finalize().to_vec()
}

/// Priv-localized key derivation per RFC 3414 §8.1.1 (DES), RFC 3826 §3.1.1 (AES-128), and draft-reeder (AES-192/256).
///
/// Per RFC 3414 §2.6 the priv-localization is an independent password-to-key derivation of
/// the priv password using the auth algorithm's hash. Applies uniformly to DES and AES.
pub fn derive_priv_key(
    _auth_localized: &[u8],
    priv_password: &str,
    engine_id: &[u8],
    auth_algo: AuthAlgo,
    priv_algo: PrivAlgo,
) -> Vec<u8> {
    let needed = priv_algo.key_len();
    let mut key = localize_key(priv_password, engine_id, auth_algo);
    while key.len() < needed {
        let extension = localize_key_from_key(&key, priv_password, engine_id, auth_algo);
        key.extend_from_slice(&extension);
    }
    key.truncate(needed);
    key
}

fn localize_key_from_key(
    prev_key: &[u8],
    password: &str,
    engine_id: &[u8],
    algo: AuthAlgo,
) -> Vec<u8> {
    let mut extended = Vec::with_capacity(prev_key.len() + password.len());
    extended.extend_from_slice(prev_key);
    extended.extend_from_slice(password.as_bytes());
    let temp = digest_bytes(&extended, algo);
    hash_localized(&temp, engine_id, algo)
}

fn digest_bytes(bytes: &[u8], algo: AuthAlgo) -> Vec<u8> {
    match algo {
        AuthAlgo::Md5 => Md5::digest(bytes).to_vec(),
        AuthAlgo::Sha1 => Sha1::digest(bytes).to_vec(),
        AuthAlgo::Sha224 => Sha224::digest(bytes).to_vec(),
        AuthAlgo::Sha256 => Sha256::digest(bytes).to_vec(),
        AuthAlgo::Sha384 => Sha384::digest(bytes).to_vec(),
        AuthAlgo::Sha512 => Sha512::digest(bytes).to_vec(),
    }
}

fn hash_localized(digest: &[u8], engine_id: &[u8], algo: AuthAlgo) -> Vec<u8> {
    let mut buf = Vec::with_capacity(digest.len() * 2 + engine_id.len());
    buf.extend_from_slice(digest);
    buf.extend_from_slice(engine_id);
    buf.extend_from_slice(digest);
    digest_bytes(&buf, algo)
}

/// Compute the HMAC over `message` with `key` and truncate to the algorithm-specific length.
pub fn hmac_truncated(algo: AuthAlgo, key: &[u8], message: &[u8]) -> Vec<u8> {
    let full = match algo {
        AuthAlgo::Md5 => {
            let mut m = <Hmac<Md5> as Mac>::new_from_slice(key).expect("hmac key len");
            m.update(message);
            m.finalize().into_bytes().to_vec()
        }
        AuthAlgo::Sha1 => {
            let mut m = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("hmac key len");
            m.update(message);
            m.finalize().into_bytes().to_vec()
        }
        AuthAlgo::Sha224 => {
            let mut m = <Hmac<Sha224> as Mac>::new_from_slice(key).expect("hmac key len");
            m.update(message);
            m.finalize().into_bytes().to_vec()
        }
        AuthAlgo::Sha256 => {
            let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key len");
            m.update(message);
            m.finalize().into_bytes().to_vec()
        }
        AuthAlgo::Sha384 => {
            let mut m = <Hmac<Sha384> as Mac>::new_from_slice(key).expect("hmac key len");
            m.update(message);
            m.finalize().into_bytes().to_vec()
        }
        AuthAlgo::Sha512 => {
            let mut m = <Hmac<Sha512> as Mac>::new_from_slice(key).expect("hmac key len");
            m.update(message);
            m.finalize().into_bytes().to_vec()
        }
    };
    let n = algo.hmac_trunc_len();
    full[..n].to_vec()
}

/// Constant-time comparison of two byte slices of the same length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("des key derivation failed: priv-localized key too short ({0} < 16)")]
    DesKeyTooShort(usize),
    #[error("aes key derivation failed: priv-localized key too short ({have} < {need})")]
    AesKeyTooShort { have: usize, need: usize },
    #[error("aes iv construction failed: engine boots/time out of range")]
    IvOutOfRange,
    #[error("des decryption failed")]
    DesDecrypt,
}

pub struct EncryptedPdu {
    pub ciphertext: Vec<u8>,
    pub privacy_parameters: Vec<u8>,
}

/// Encrypt a scopedPDU under the configured privacy algorithm. `salt` is caller-supplied.
pub fn encrypt_scoped_pdu(
    algo: PrivAlgo,
    priv_key: &[u8],
    engine_boots: u32,
    engine_time: u32,
    salt: [u8; 8],
    plaintext: &[u8],
) -> Result<EncryptedPdu, CryptoError> {
    match algo {
        PrivAlgo::Des => {
            if priv_key.len() < 16 {
                return Err(CryptoError::DesKeyTooShort(priv_key.len()));
            }
            let enc_key: [u8; 8] = priv_key[0..8].try_into().expect("8 bytes");
            let pre_iv: [u8; 8] = priv_key[8..16].try_into().expect("8 bytes");
            let iv: [u8; 8] = xor8(pre_iv, salt);
            let ciphertext = des_cbc_encrypt(&enc_key, &iv, plaintext);
            Ok(EncryptedPdu {
                ciphertext,
                privacy_parameters: salt.to_vec(),
            })
        }
        PrivAlgo::Aes128 | PrivAlgo::Aes192 | PrivAlgo::Aes256 => {
            let need = algo.key_len();
            if priv_key.len() < need {
                return Err(CryptoError::AesKeyTooShort {
                    have: priv_key.len(),
                    need,
                });
            }
            let iv = aes_iv(engine_boots, engine_time, salt);
            let ciphertext = aes_cfb_encrypt(algo, &priv_key[..need], &iv, plaintext);
            Ok(EncryptedPdu {
                ciphertext,
                privacy_parameters: salt.to_vec(),
            })
        }
    }
}

pub fn decrypt_scoped_pdu(
    algo: PrivAlgo,
    priv_key: &[u8],
    engine_boots: u32,
    engine_time: u32,
    privacy_parameters: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match algo {
        PrivAlgo::Des => {
            if priv_key.len() < 16 {
                return Err(CryptoError::DesKeyTooShort(priv_key.len()));
            }
            if privacy_parameters.len() != 8 {
                return Err(CryptoError::DesDecrypt);
            }
            let enc_key: [u8; 8] = priv_key[0..8].try_into().expect("8 bytes");
            let pre_iv: [u8; 8] = priv_key[8..16].try_into().expect("8 bytes");
            let salt: [u8; 8] = privacy_parameters.try_into().expect("8 bytes");
            let iv = xor8(pre_iv, salt);
            des_cbc_decrypt(&enc_key, &iv, ciphertext).ok_or(CryptoError::DesDecrypt)
        }
        PrivAlgo::Aes128 | PrivAlgo::Aes192 | PrivAlgo::Aes256 => {
            let need = algo.key_len();
            if priv_key.len() < need {
                return Err(CryptoError::AesKeyTooShort {
                    have: priv_key.len(),
                    need,
                });
            }
            if privacy_parameters.len() != 8 {
                return Err(CryptoError::DesDecrypt);
            }
            let salt: [u8; 8] = privacy_parameters.try_into().expect("8 bytes");
            let iv = aes_iv(engine_boots, engine_time, salt);
            Ok(aes_cfb_decrypt(algo, &priv_key[..need], &iv, ciphertext))
        }
    }
}

fn xor8(a: [u8; 8], b: [u8; 8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn aes_iv(engine_boots: u32, engine_time: u32, salt: [u8; 8]) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[0..4].copy_from_slice(&engine_boots.to_be_bytes());
    iv[4..8].copy_from_slice(&engine_time.to_be_bytes());
    iv[8..16].copy_from_slice(&salt);
    iv
}

type DesCbcEnc = cbc::Encryptor<des::Des>;
type DesCbcDec = cbc::Decryptor<des::Des>;

fn des_cbc_encrypt(key: &[u8; 8], iv: &[u8; 8], plaintext: &[u8]) -> Vec<u8> {
    let mut padded = plaintext.to_vec();
    let rem = padded.len() % 8;
    if rem != 0 {
        padded.resize(padded.len() + (8 - rem), 0);
    }
    let cipher = DesCbcEnc::new(key.into(), iv.into());
    cipher.encrypt_padded_vec_mut::<NoPadding>(&padded)
}

fn des_cbc_decrypt(key: &[u8; 8], iv: &[u8; 8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(8) {
        return None;
    }
    let cipher = DesCbcDec::new(key.into(), iv.into());
    cipher.decrypt_padded_vec_mut::<NoPadding>(ciphertext).ok()
}

type Aes128Cfb = cfb_mode::Encryptor<aes::Aes128>;
type Aes192Cfb = cfb_mode::Encryptor<aes::Aes192>;
type Aes256Cfb = cfb_mode::Encryptor<aes::Aes256>;
type Aes128CfbDec = cfb_mode::Decryptor<aes::Aes128>;
type Aes192CfbDec = cfb_mode::Decryptor<aes::Aes192>;
type Aes256CfbDec = cfb_mode::Decryptor<aes::Aes256>;

fn aes_cfb_encrypt(algo: PrivAlgo, key: &[u8], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let mut out = plaintext.to_vec();
    match algo {
        PrivAlgo::Aes128 => Aes128Cfb::new(key.into(), iv.into()).encrypt(&mut out),
        PrivAlgo::Aes192 => Aes192Cfb::new(key.into(), iv.into()).encrypt(&mut out),
        PrivAlgo::Aes256 => Aes256Cfb::new(key.into(), iv.into()).encrypt(&mut out),
        PrivAlgo::Des => unreachable!("aes_cfb_encrypt called with Des"),
    }
    out
}

fn aes_cfb_decrypt(algo: PrivAlgo, key: &[u8], iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = ciphertext.to_vec();
    match algo {
        PrivAlgo::Aes128 => Aes128CfbDec::new(key.into(), iv.into()).decrypt(&mut out),
        PrivAlgo::Aes192 => Aes192CfbDec::new(key.into(), iv.into()).decrypt(&mut out),
        PrivAlgo::Aes256 => Aes256CfbDec::new(key.into(), iv.into()).decrypt(&mut out),
        PrivAlgo::Des => unreachable!("aes_cfb_decrypt called with Des"),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine_id_rfc_3414() -> Vec<u8> {
        (0..=11)
            .map(|i| if i == 11 { 0x02u8 } else { 0x00u8 })
            .collect()
    }

    #[test]
    fn key_localization_md5_matches_rfc_3414_test_vector() {
        let engine_id = engine_id_rfc_3414();
        let localized = localize_key("maplesyrup", &engine_id, AuthAlgo::Md5);
        let expected: [u8; 16] = [
            0x52, 0x6f, 0x5e, 0xed, 0x9f, 0xcc, 0xe2, 0x6f, 0x89, 0x64, 0xc2, 0x93, 0x07, 0x87,
            0xd8, 0x2b,
        ];
        assert_eq!(localized, expected.to_vec());
    }

    #[test]
    fn key_localization_sha1_matches_rfc_3414_test_vector() {
        let engine_id = engine_id_rfc_3414();
        let localized = localize_key("maplesyrup", &engine_id, AuthAlgo::Sha1);
        let expected: [u8; 20] = [
            0x66, 0x95, 0xfe, 0xbc, 0x92, 0x88, 0xe3, 0x62, 0x82, 0x23, 0x5f, 0xc7, 0x15, 0x1f,
            0x12, 0x84, 0x97, 0xb3, 0x8f, 0x3f,
        ];
        assert_eq!(localized, expected.to_vec());
    }

    #[test]
    fn key_localization_sha224_matches_rfc_7860_test_vector() {
        let engine_id = engine_id_rfc_3414();
        let localized = localize_key("maplesyrup", &engine_id, AuthAlgo::Sha224);
        let expected: [u8; 28] = [
            0x0b, 0xd8, 0x82, 0x7c, 0x6e, 0x29, 0xf8, 0x06, 0x5e, 0x08, 0xe0, 0x92, 0x37, 0xf1,
            0x77, 0xe4, 0x10, 0xf6, 0x9b, 0x90, 0xe1, 0x78, 0x2b, 0xe6, 0x82, 0x07, 0x56, 0x74,
        ];
        assert_eq!(localized, expected.to_vec());
    }

    #[test]
    fn key_localization_sha256_matches_rfc_7860_test_vector() {
        let engine_id = engine_id_rfc_3414();
        let localized = localize_key("maplesyrup", &engine_id, AuthAlgo::Sha256);
        let expected: [u8; 32] = [
            0x89, 0x82, 0xe0, 0xe5, 0x49, 0xe8, 0x66, 0xdb, 0x36, 0x1a, 0x6b, 0x62, 0x5d, 0x84,
            0xcc, 0xcc, 0x11, 0x16, 0x2d, 0x45, 0x3e, 0xe8, 0xce, 0x3a, 0x64, 0x45, 0xc2, 0xd6,
            0x77, 0x6f, 0x0f, 0x8b,
        ];
        assert_eq!(localized, expected.to_vec());
    }

    #[test]
    fn key_localization_sha384_matches_rfc_7860_test_vector() {
        let engine_id = engine_id_rfc_3414();
        let localized = localize_key("maplesyrup", &engine_id, AuthAlgo::Sha384);
        let expected: [u8; 48] = [
            0x3b, 0x29, 0x8f, 0x16, 0x16, 0x4a, 0x11, 0x18, 0x42, 0x79, 0xd5, 0x43, 0x2b, 0xf1,
            0x69, 0xe2, 0xd2, 0xa4, 0x83, 0x07, 0xde, 0x02, 0xb3, 0xd3, 0xf7, 0xe2, 0xb4, 0xf3,
            0x6e, 0xb6, 0xf0, 0x45, 0x5a, 0x53, 0x68, 0x9a, 0x39, 0x37, 0xee, 0xa0, 0x73, 0x19,
            0xa6, 0x33, 0xd2, 0xcc, 0xba, 0x78,
        ];
        assert_eq!(localized, expected.to_vec());
    }

    #[test]
    fn key_localization_sha512_matches_rfc_7860_test_vector() {
        let engine_id = engine_id_rfc_3414();
        let localized = localize_key("maplesyrup", &engine_id, AuthAlgo::Sha512);
        let expected: [u8; 64] = [
            0x22, 0xa5, 0xa3, 0x6c, 0xed, 0xfc, 0xc0, 0x85, 0x80, 0x7a, 0x12, 0x8d, 0x7b, 0xc6,
            0xc2, 0x38, 0x21, 0x67, 0xad, 0x6c, 0x0d, 0xbc, 0x5f, 0xdf, 0xf8, 0x56, 0x74, 0x0f,
            0x3d, 0x84, 0xc0, 0x99, 0xad, 0x1e, 0xa8, 0x7a, 0x8d, 0xb0, 0x96, 0x71, 0x4d, 0x97,
            0x88, 0xbd, 0x54, 0x40, 0x47, 0xc9, 0x02, 0x1e, 0x42, 0x29, 0xce, 0x27, 0xe4, 0xc0,
            0xa6, 0x92, 0x50, 0xad, 0xfc, 0xff, 0xbb, 0x0b,
        ];
        assert_eq!(localized, expected.to_vec());
    }

    #[test]
    fn hmac_truncation_md5_uses_12_bytes() {
        let key = vec![0x11u8; 16];
        let out = hmac_truncated(AuthAlgo::Md5, &key, b"hello");
        assert_eq!(out.len(), 12);
    }

    #[test]
    fn hmac_truncation_sha1_uses_12_bytes() {
        let key = vec![0x11u8; 20];
        let out = hmac_truncated(AuthAlgo::Sha1, &key, b"hello");
        assert_eq!(out.len(), 12);
    }

    #[test]
    fn hmac_truncation_sha256_uses_24_bytes() {
        let key = vec![0x11u8; 32];
        let out = hmac_truncated(AuthAlgo::Sha256, &key, b"hello");
        assert_eq!(out.len(), 24);
    }

    #[test]
    fn hmac_truncation_sha512_uses_48_bytes() {
        let key = vec![0x11u8; 64];
        let out = hmac_truncated(AuthAlgo::Sha512, &key, b"hello");
        assert_eq!(out.len(), 48);
    }

    #[test]
    fn hmac_truncation_sha224_384_use_expected_lengths() {
        assert_eq!(hmac_truncated(AuthAlgo::Sha224, &[0u8; 28], b"x").len(), 16);
        assert_eq!(hmac_truncated(AuthAlgo::Sha384, &[0u8; 48], b"x").len(), 32);
    }

    #[test]
    fn ct_eq_returns_true_on_equal_slices() {
        assert!(ct_eq(&[1, 2, 3, 4], &[1, 2, 3, 4]));
    }

    #[test]
    fn ct_eq_returns_false_on_unequal_length() {
        assert!(!ct_eq(&[1, 2], &[1, 2, 3]));
    }

    #[test]
    fn ct_eq_returns_false_on_different_content() {
        assert!(!ct_eq(&[1, 2, 3, 4], &[1, 2, 3, 5]));
    }

    #[test]
    fn des_cbc_encrypts_and_decrypts_scoped_pdu() {
        let engine_id = engine_id_rfc_3414();
        let auth_key = localize_key("maplesyrup", &engine_id, AuthAlgo::Md5);
        let priv_key = derive_priv_key(
            &auth_key,
            "maplesyrup",
            &engine_id,
            AuthAlgo::Md5,
            PrivAlgo::Des,
        );
        let plaintext = b"scoped-pdu-data-x";
        let salt: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let enc =
            encrypt_scoped_pdu(PrivAlgo::Des, &priv_key, 1, 100, salt, plaintext).expect("encrypt");
        assert_eq!(enc.privacy_parameters.len(), 8);
        assert_ne!(enc.ciphertext.as_slice(), plaintext);
        let dec = decrypt_scoped_pdu(
            PrivAlgo::Des,
            &priv_key,
            1,
            100,
            &enc.privacy_parameters,
            &enc.ciphertext,
        )
        .expect("decrypt");
        assert!(dec.len() >= plaintext.len());
        assert_eq!(&dec[..plaintext.len()], plaintext);
    }

    #[test]
    fn des_cbc_encrypt_uses_zero_padding_not_pkcs7() {
        let engine_id = engine_id_rfc_3414();
        let auth_key = localize_key("maplesyrup", &engine_id, AuthAlgo::Md5);
        let priv_key = derive_priv_key(
            &auth_key,
            "maplesyrup",
            &engine_id,
            AuthAlgo::Md5,
            PrivAlgo::Des,
        );
        let plaintext = [0xAAu8; 15];
        let salt: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let enc = encrypt_scoped_pdu(PrivAlgo::Des, &priv_key, 1, 100, salt, &plaintext)
            .expect("encrypt");
        assert_eq!(enc.ciphertext.len(), 16);
        let dec = decrypt_scoped_pdu(
            PrivAlgo::Des,
            &priv_key,
            1,
            100,
            &enc.privacy_parameters,
            &enc.ciphertext,
        )
        .expect("decrypt");
        assert_eq!(dec.len(), 16);
        assert_eq!(&dec[..15], &plaintext[..]);
        assert_eq!(dec[15], 0);
    }

    #[test]
    fn des_cbc_round_trip_preserves_bytes_without_length_growth() {
        let engine_id = engine_id_rfc_3414();
        let auth_key = localize_key("maplesyrup", &engine_id, AuthAlgo::Sha1);
        let priv_key = derive_priv_key(
            &auth_key,
            "maplesyrup",
            &engine_id,
            AuthAlgo::Sha1,
            PrivAlgo::Des,
        );
        for n in [1usize, 8, 9, 15, 16, 17, 33, 64, 100] {
            let plaintext: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_add(1)).collect();
            let salt: [u8; 8] = [n as u8; 8];
            let enc = encrypt_scoped_pdu(PrivAlgo::Des, &priv_key, 1, 100, salt, &plaintext)
                .expect("encrypt");
            assert_eq!(enc.ciphertext.len() % 8, 0);
            assert!(enc.ciphertext.len() < n + 8);
            let dec = decrypt_scoped_pdu(
                PrivAlgo::Des,
                &priv_key,
                1,
                100,
                &enc.privacy_parameters,
                &enc.ciphertext,
            )
            .expect("decrypt");
            assert!(dec.len() >= n);
            assert_eq!(&dec[..n], &plaintext[..]);
        }
    }

    #[test]
    fn aes128_cfb_encrypts_and_decrypts_scoped_pdu() {
        let engine_id = engine_id_rfc_3414();
        let auth_key = localize_key("authpass", &engine_id, AuthAlgo::Sha256);
        let priv_key = derive_priv_key(
            &auth_key,
            "privpass",
            &engine_id,
            AuthAlgo::Sha256,
            PrivAlgo::Aes128,
        );
        assert_eq!(priv_key.len(), 16);
        let plaintext = b"authPriv-payload-arbitrary-length";
        let salt: [u8; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
        let enc = encrypt_scoped_pdu(PrivAlgo::Aes128, &priv_key, 42, 999_999, salt, plaintext)
            .expect("encrypt");
        assert_eq!(enc.ciphertext.len(), plaintext.len());
        let dec = decrypt_scoped_pdu(
            PrivAlgo::Aes128,
            &priv_key,
            42,
            999_999,
            &enc.privacy_parameters,
            &enc.ciphertext,
        )
        .expect("decrypt");
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn aes192_key_derivation_extends_via_reeder_from_priv_password() {
        let engine_id = engine_id_rfc_3414();
        let auth_key = localize_key("authpass", &engine_id, AuthAlgo::Md5);
        let priv_localized = localize_key("privpass", &engine_id, AuthAlgo::Md5);
        assert_eq!(priv_localized.len(), 16);
        let priv_key = derive_priv_key(
            &auth_key,
            "privpass",
            &engine_id,
            AuthAlgo::Md5,
            PrivAlgo::Aes192,
        );
        assert_eq!(priv_key.len(), 24);
        assert_eq!(priv_key[..16], priv_localized[..]);
    }

    #[test]
    fn aes256_key_derivation_extends_via_reeder_from_priv_password() {
        let engine_id = engine_id_rfc_3414();
        let auth_key = localize_key("authpass", &engine_id, AuthAlgo::Sha1);
        let priv_localized = localize_key("privpass", &engine_id, AuthAlgo::Sha1);
        assert_eq!(priv_localized.len(), 20);
        let priv_key = derive_priv_key(
            &auth_key,
            "privpass",
            &engine_id,
            AuthAlgo::Sha1,
            PrivAlgo::Aes256,
        );
        assert_eq!(priv_key.len(), 32);
        assert_eq!(priv_key[..20], priv_localized[..]);
    }

    #[test]
    fn derive_priv_key_aes128_uses_independently_localized_priv_password() {
        let engine_id = engine_id_rfc_3414();
        let auth_a = localize_key("auth-A", &engine_id, AuthAlgo::Sha256);
        let auth_c = localize_key("auth-C", &engine_id, AuthAlgo::Sha256);
        let priv_from_a = derive_priv_key(
            &auth_a,
            "priv-B",
            &engine_id,
            AuthAlgo::Sha256,
            PrivAlgo::Aes128,
        );
        let priv_from_c = derive_priv_key(
            &auth_c,
            "priv-B",
            &engine_id,
            AuthAlgo::Sha256,
            PrivAlgo::Aes128,
        );
        assert_eq!(priv_from_a.len(), 16);
        assert_eq!(priv_from_a, priv_from_c);
    }

    #[test]
    fn derive_priv_key_des_uses_independently_localized_priv_password() {
        let engine_id = engine_id_rfc_3414();
        let auth_key_a = localize_key("auth-a", &engine_id, AuthAlgo::Sha1);
        let auth_key_c = localize_key("auth-c", &engine_id, AuthAlgo::Sha1);
        let priv_from_a = derive_priv_key(
            &auth_key_a,
            "shared-priv",
            &engine_id,
            AuthAlgo::Sha1,
            PrivAlgo::Des,
        );
        let priv_from_c = derive_priv_key(
            &auth_key_c,
            "shared-priv",
            &engine_id,
            AuthAlgo::Sha1,
            PrivAlgo::Des,
        );
        assert_eq!(priv_from_a.len(), 16);
        assert_eq!(priv_from_a, priv_from_c);
        let priv_localized = localize_key("shared-priv", &engine_id, AuthAlgo::Sha1);
        assert_eq!(&priv_from_a[..], &priv_localized[..16]);
    }

    #[test]
    fn aes192_encrypts_and_decrypts_scoped_pdu() {
        let engine_id = engine_id_rfc_3414();
        let auth_key = localize_key("authpass", &engine_id, AuthAlgo::Sha256);
        let priv_key = derive_priv_key(
            &auth_key,
            "privpass",
            &engine_id,
            AuthAlgo::Sha256,
            PrivAlgo::Aes192,
        );
        let plaintext = b"aes192-payload";
        let salt: [u8; 8] = [9, 9, 9, 9, 9, 9, 9, 9];
        let enc = encrypt_scoped_pdu(PrivAlgo::Aes192, &priv_key, 3, 300, salt, plaintext)
            .expect("encrypt");
        let dec = decrypt_scoped_pdu(
            PrivAlgo::Aes192,
            &priv_key,
            3,
            300,
            &enc.privacy_parameters,
            &enc.ciphertext,
        )
        .expect("decrypt");
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn aes256_encrypts_and_decrypts_scoped_pdu() {
        let engine_id = engine_id_rfc_3414();
        let auth_key = localize_key("authpass", &engine_id, AuthAlgo::Sha512);
        let priv_key = derive_priv_key(
            &auth_key,
            "privpass",
            &engine_id,
            AuthAlgo::Sha512,
            PrivAlgo::Aes256,
        );
        assert_eq!(priv_key.len(), 32);
        let plaintext = b"aes256-longer-payload";
        let salt: [u8; 8] = [1, 1, 1, 1, 1, 1, 1, 1];
        let enc = encrypt_scoped_pdu(PrivAlgo::Aes256, &priv_key, 7, 700, salt, plaintext)
            .expect("encrypt");
        let dec = decrypt_scoped_pdu(
            PrivAlgo::Aes256,
            &priv_key,
            7,
            700,
            &enc.privacy_parameters,
            &enc.ciphertext,
        )
        .expect("decrypt");
        assert_eq!(dec, plaintext);
    }
}
