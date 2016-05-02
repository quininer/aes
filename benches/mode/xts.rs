use test::Bencher;
use openssl::crypto::symm::{ encrypt, Type };
use aes::mode::Xts;
use aes::cipher::CtsBlockEncrypt;


#[bench]
fn bench_aes_xts(b: &mut Bencher) {
    let key1 = rand!(16);
    let key2 = rand!(16);
    let i = rand!(16);
    let plaintext = rand!(63);

    b.iter(|| Xts::new(&key1, &key2, &i).encrypt(&plaintext));
}

#[bench]
fn bench_openssl_xts(b: &mut Bencher) {
    let key1 = rand!(16);
    let key2 = rand!(16);
    let i = rand!(16);
    let plaintext = rand!(63);

    b.iter(|| encrypt(
        Type::AES_128_XTS,
        &[key1.clone(), key2.clone()].concat(),
        &i,
        &plaintext
    ));
}
