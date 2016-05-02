use crypto::aes::KeySize;
use crypto::aes_gcm::AesGcm;
use crypto::aead::AeadEncryptor;
use aes::mode::Gcm;
use aes::cipher::{
    DecryptFail,
    AeadStreamEncrypt, AeadStreamDecrypt
};


#[test]
fn test_gcm_encrypt() {
    let key = rand!(16);
    let nonce = rand!(12);
    let plaintext = rand!(rand!(choose 15..65));

    let (mut crypto_out, mut crypto_tag) = (vec![0; plaintext.len()], vec![0; 16]);
    AesGcm::new(KeySize::KeySize128, &key, &nonce, &nonce)
        .encrypt(&plaintext, &mut crypto_out, &mut crypto_tag);
    assert_eq!(
        Gcm::new(&key, &nonce, &nonce).encrypt(&plaintext),
        (crypto_out, crypto_tag)
    );
}

#[test]
fn test_gcm_decrypt() {
    let key = rand!(16);
    let nonce = rand!(12);
    let plaintext = rand!(rand!(choose 15..65));

    let (ciphertext, tag) = Gcm::new(&key, &nonce, &nonce).encrypt(&plaintext);

    assert_eq!(
        Gcm::new(&key, &nonce, &nonce).decrypt(&ciphertext[1..], &tag),
        Err(DecryptFail::Auth)
    );
    assert_eq!(
        Gcm::new(&key, &nonce, &nonce).decrypt(&ciphertext, &nonce),
        Err(DecryptFail::Auth)
    );
    assert_eq!(
        Gcm::new(&key, &nonce, &nonce).decrypt(&ciphertext, &tag),
        Ok(plaintext)
    );
}
