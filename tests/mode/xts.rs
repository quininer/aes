use openssl::crypto::symm::{ encrypt, Type };
use aes::mode::Xts;
use aes::cipher::{ CtsBlockEncrypt, CtsBlockDecrypt };


#[test]
fn test_xts_encrypt() {
    let key1 = rand!(16);
    let key2 = rand!(16);
    let i = rand!(16);
    let plaintext = rand!(rand!(choose 16..65));

    let ciphertext = Xts::new(&key1, &key2, &i).encrypt(&plaintext);
    assert_eq!(ciphertext.len(), plaintext.len());
    assert_eq!(
        ciphertext,
        encrypt(Type::AES_128_XTS, &[key1, key2].concat(), &i, &plaintext)
    );
}

#[test]
fn test_xts_decrypt() {
    let key1 = rand!(16);
    let key2 = rand!(16);
    let i = rand!(16);
    let plaintext = rand!(rand!(choose 16..65));

    let ciphertext = Xts::new(&key1, &key2, &i).encrypt(&plaintext);
    assert_eq!(ciphertext.len(), plaintext.len());
    assert_eq!(
        Xts::new(&key1, &key2, &i).decrypt(&ciphertext),
        plaintext
    );

    assert_eq!(
        Xts::new(&key1, &key2, &i).decrypt(&encrypt(
            Type::AES_128_XTS,
            &[key1, key2].concat(),
            &i,
            &plaintext
        )),
        plaintext
    )
}
