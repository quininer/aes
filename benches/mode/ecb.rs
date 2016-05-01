use test::Bencher;
use openssl::crypto::symm::{ encrypt, Type };
use aes::mode::Ecb;
use aes::utils::padding::Pkcs7Padding;
use aes::cipher::BlockEncrypt;


#[bench]
fn bench_aes_ecb(b: &mut Bencher) {
    let key = rand!(16);
    let plaintext = rand!(63);

    b.iter(|| Ecb::new(&key).encrypt::<Pkcs7Padding>(&plaintext));
}

#[bench]
fn bench_openssl_ecb(b: &mut Bencher) {
    let key = rand!(16);
    let plaintext = rand!(63);

    b.iter(|| encrypt(Type::AES_128_ECB, &key, &[], &plaintext));
}
