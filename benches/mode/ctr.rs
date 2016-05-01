use test::Bencher;
use openssl::crypto::symm::{ encrypt, Type };
use aes::mode::Ctr;
use aes::cipher::StreamEncrypt;


#[bench]
fn bench_aes_ctr(b: &mut Bencher) {
    let key = rand!(16);
    let ctr = rand!(16);
    let plaintext = rand!(63);

    b.iter(|| Ctr::new(&key, &ctr).encrypt(&plaintext));
}

#[bench]
fn bench_openssl_ctr(b: &mut Bencher) {
    let key = rand!(16);
    let ctr = rand!(16);
    let plaintext = rand!(63);

    b.iter(|| encrypt(Type::AES_128_CTR, &key, &ctr, &plaintext));
}
