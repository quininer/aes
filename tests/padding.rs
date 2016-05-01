extern crate aes;

use aes::utils::padding::Padding;


#[test]
fn test_nopadding() {
    use aes::utils::padding::NoPadding;

    let plaintext = b"YELLOW SUBMARINE";

    assert_eq!(
        NoPadding::padding(plaintext, 20),
        plaintext
    );

    assert_eq!(
        NoPadding::unpadding(plaintext, 20).unwrap(),
        plaintext
    );
}

#[test]
fn test_pkcs7padding() {
    use aes::utils::padding::{ Pkcs7Padding, PaddingError };

    let plaintext = b"YELLOW SUBMARINE";

    assert_eq!(
        Pkcs7Padding::padding(plaintext, 20),
        b"YELLOW SUBMARINE\x04\x04\x04\x04"
    );
    assert_eq!(
        Pkcs7Padding::padding(plaintext, 16),
        b"YELLOW SUBMARINE\
        \x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
    );

    assert_eq!(
        Pkcs7Padding::unpadding(
            &Pkcs7Padding::padding(plaintext, 20),
            20
        ).unwrap(),
        plaintext
    );
    assert_eq!(
        Pkcs7Padding::unpadding(
            &Pkcs7Padding::padding(plaintext, 20),
            16
        ),
        Err(PaddingError::BadData)
    );
    assert_eq!(
        Pkcs7Padding::unpadding(
            &Pkcs7Padding::padding(plaintext, 16),
            20
        ),
        Err(PaddingError::BadData)
    );
    assert_eq!(
        Pkcs7Padding::unpadding(plaintext, 16),
        Err(PaddingError::BadPadding)
    );
}
