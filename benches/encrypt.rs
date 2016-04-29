#![feature(test)]

extern crate test;
extern crate rand;
extern crate openssl;
extern crate aes;

#[path = "../tests/rand.rs"]
#[macro_use] mod rand_macro;

use test::Bencher;


#[bench]
fn bench_openssl_ebc_encrypt(b: &mut Bencher) {
    use openssl::crypto::symm::{ Crypter, Type, Mode };

    let key = rand!(16);
    let plaintext = rand!(16);
    let cipher = Crypter::new(Type::AES_128_ECB);
    cipher.init(Mode::Encrypt, &key, &[]);
    cipher.pad(false);

    b.iter(|| {
        cipher.update(&plaintext)
    });
}
