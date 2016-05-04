use test::Bencher;
use crypto::aes::KeySize;
use crypto::aes_gcm::AesGcm;
use crypto::aead::AeadEncryptor;
use aes::mode::Gcm;
use aes::cipher::AeadStreamEncrypt;


#[bench]
fn bench_aes_gcm(b: &mut Bencher) {
    let key = rand!(16);
    let nonce = rand!(12);
    let plaintext = rand!(63);

    b.iter(|| Gcm::new(&key, &nonce, &nonce).encrypt(&plaintext));
}

#[bench]
fn bench_crypto_gcm(b: &mut Bencher) {
    let key = rand!(16);
    let nonce = rand!(12);
    let plaintext = rand!(63);

    b.iter(|| {
        let (mut out, mut tag) = (
            vec![0; plaintext.len()],
            vec![0; 16]
        );
        AesGcm::new(KeySize::KeySize128, &key, &nonce, &nonce)
            .encrypt(&plaintext, &mut out, &mut tag);
        (out, tag)
    });
}
