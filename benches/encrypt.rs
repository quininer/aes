#![feature(test)]

extern crate test;
extern crate rand;
extern crate openssl;
extern crate crypto;
extern crate aes;

#[path = "../tests/rand.rs"]
#[macro_use] mod rand_macro;
mod mode;

use test::Bencher;


#[bench]
fn bench_openssl_ebc_encrypt(b: &mut Bencher) {
    use openssl::crypto::symm::{ Crypter, Type, Mode };

    let key = rand!(16);
    let plaintext = rand!(16);

    b.iter(|| {
        let cipher = Crypter::new(Type::AES_128_ECB);
        cipher.init(Mode::Encrypt, &key, &[]);
        cipher.pad(false);
        cipher.update(&plaintext);
    });
}

#[bench]
fn bench_crypto_encrypt(b: &mut Bencher) {
    use crypto::{ buffer, aes, blockmodes };

    let key = rand!(16);
    let plaintext = rand!(16);

    b.iter(|| {
        let mut cipher = aes::ecb_encryptor(
            aes::KeySize::KeySize128,
            &key,
            blockmodes::NoPadding
        );
        let mut out = [0; 16];
        let mut read_buffer = buffer::RefReadBuffer::new(&plaintext);
        let mut write_buffer = buffer::RefWriteBuffer::new(&mut out);
        cipher.encrypt(&mut read_buffer, &mut write_buffer, true).ok();
    });
}

#[bench]
fn bench_aes_encrypt(b: &mut Bencher) {
    use aes::AES;
    use aes::cipher::SingleBlockEncrypt;

    let key = rand!(16);
    let plaintext = rand!(16);

    b.iter(|| AES::new(&key).encrypt(&plaintext))
}
