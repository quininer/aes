use openssl::crypto::symm::{ Crypter, Type, Mode };
use aes::mode::Ctr;
use aes::cipher::{ StreamEncrypt, StreamDecrypt };


#[test]
fn test_ctr_test() {
    let key = [1; 16];
    let ctr = [3; 16];
    let plaintext = [2; 33];

    assert_eq!(
        Ctr::new(&key, &ctr).encrypt(&plaintext),
        vec![
            0x64, 0x3e, 0x05, 0x19, 0x79, 0x78, 0xd7, 0x45, 0xa9, 0x10, 0x5f,
            0xd8, 0x4c, 0xd7, 0xe6, 0xb1, 0x5f, 0x66, 0xc6, 0x17, 0x4b, 0x25,
            0xea, 0x24, 0xe6, 0xf9, 0x19, 0x09, 0xb7, 0xdd, 0x84, 0xfb, 0x86
        ]
    );
}

#[test]
fn test_ctr_encrypt() {
    let key = rand!(16);
    let ctr = rand!(16);
    let plaintext = rand!(rand!(choose 15..65));

    let mut cipher = Ctr::new(&key, &ctr);
    let os_cipher = Crypter::new(Type::AES_128_CTR);
    os_cipher.init(Mode::Encrypt, &key, &ctr);

    let ciphertext1 = os_cipher.update(&plaintext);

    assert_eq!(
        cipher.encrypt(&plaintext),
        ciphertext1
    );

    let ciphertext2 = os_cipher.update(&plaintext);

    assert_eq!(
        cipher.encrypt(&plaintext),
        ciphertext2
    );

    assert!(ciphertext1 != ciphertext2);
}

#[test]
fn test_ctr_decrypt() {
    let key = rand!(16);
    let ctr = rand!(16);
    let plaintext = rand!(rand!(choose 15..65));

    assert_eq!(
        Ctr::new(&key, &ctr).decrypt(
            &Ctr::new(&key, &ctr).encrypt(&plaintext)
        ),
        plaintext
    );
}
