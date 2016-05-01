use openssl::crypto::symm::{ encrypt, Type };
use aes::mode::Ecb;
use aes::utils::padding::Pkcs7Padding;
use aes::cipher::{ BlockEncrypt, BlockDecrypt };


#[test]
fn test_ecb_encrypt() {
    let key = rand!(16);
    let plaintext = rand!(rand!(choose 15..65));

    assert_eq!(
        Ecb::new(&key).encrypt::<Pkcs7Padding>(&plaintext),
        encrypt(Type::AES_128_ECB, &key, &[], &plaintext)
    );
}

#[test]
fn test_ecb_decrypt() {
    let key = rand!(16);
    let plaintext = rand!(rand!(choose 15..55));

    assert_eq!(
        Ecb::new(&key).decrypt::<Pkcs7Padding>(
            &Ecb::new(&key).encrypt::<Pkcs7Padding>(&plaintext)
        ).unwrap(),
        plaintext
    );

    assert_eq!(
        Ecb::new(&key).decrypt::<Pkcs7Padding>(
            &encrypt(Type::AES_128_ECB, &key, &[], &plaintext)
        ),
        Ok(plaintext)
    );
}
