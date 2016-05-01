use test::Bencher;
use openssl::crypto::symm::{ encrypt, Type };
use aes::mode::Cbc;
use aes::utils::padding::Pkcs7Padding;
use aes::cipher::BlockEncrypt;


#[bench]
fn bench_aes_cbc(b: &mut Bencher) {
    let key = rand!(16);
    let iv = rand!(16);
    let plaintext = rand!(64);

    b.iter(|| Cbc::new(&key, &iv).encrypt::<Pkcs7Padding>(&plaintext));
}

#[bench]
fn bench_openssl_cbc(b: &mut Bencher) {
    let key = rand!(16);
    let iv = rand!(16);
    let plaintext = rand!(64);

    b.iter(|| encrypt(Type::AES_128_CBC, &key, &iv, &plaintext));
}
