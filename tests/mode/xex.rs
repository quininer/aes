use aes::AES;
use aes::mode::Xex;
use aes::utils::padding::Pkcs7Padding;
use aes::cipher::{ BlockEncrypt, BlockDecrypt };


#[test]
fn test_xex_decrypt() {
    let key1 = rand!(16);
    let key2 = rand!(16);
    let i = rand!(16);
    let plaintext = rand!(rand!(choose 15..65));

    assert_eq!(
        Xex::new(&key1, &key2, &i).decrypt::<Pkcs7Padding>(
            &Xex::new(&key1, &key2, &i).encrypt::<Pkcs7Padding>(&plaintext)
        ),
        Ok(plaintext)
    );
}

#[test]
fn test_xex_next_tweak() {
    assert_eq!(
        Xex::<AES>::next_tweak(&[0; 16]),
        [0; 16]
    );
    assert_eq!(
        Xex::<AES>::next_tweak(&[[1, 2, 3, 4]; 4].concat()),
        [[2, 4, 6, 8]; 4].concat()
    );
}
