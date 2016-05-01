use openssl::crypto::symm::{ encrypt, Type };
use aes::mode::Cbc;
use aes::utils::padding::Pkcs7Padding;
use aes::cipher::{ BlockEncrypt, BlockDecrypt };


#[test]
fn test_cbc_encrypt() {
    let key = rand!(16);
    let iv = rand!(16);
    let plaintext = rand!(rand!(choose 15..65));

    assert_eq!(
        Cbc::new(&key, &iv).encrypt::<Pkcs7Padding>(&plaintext),
        encrypt(Type::AES_128_CBC, &key, &iv, &plaintext)
    );
}

#[test]
fn test_cbc_decrypt() {
    let key = rand!(16);
    let iv = rand!(16);
    let plaintext = rand!(rand!(choose 15..65));

    assert_eq!(
        Cbc::new(&key, &iv).decrypt::<Pkcs7Padding>(
            &Cbc::new(&key, &iv).encrypt::<Pkcs7Padding>(&plaintext)
        ).unwrap(),
        plaintext
    );

    assert_eq!(
        Cbc::new(&key, &iv).decrypt::<Pkcs7Padding>(
            &encrypt(Type::AES_128_CBC, &key, &iv, &plaintext)
        ).unwrap(),
        plaintext
    );
}
