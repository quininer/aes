#![feature(test)]

extern crate test;
extern crate rand;
extern crate crypto;
extern crate aes;

#[path = "../tests/rand.rs"]
#[macro_use] mod rand_macro;

use test::Bencher;


#[bench]
fn bench_aes_ghash(b: &mut Bencher) {
    use aes::utils::ghash::Ghash;

    let key = rand!(16);
    let aad = rand!(15);
    let text = rand!(55);

    b.iter(|| {
        Ghash::new(&key, &aad).input(&text).result()
    });
}

#[bench]
fn bench_crypto_ghash(b: &mut Bencher) {
    use crypto::ghash::Ghash;

    let key = rand!(16);
    let aad = rand!(15);
    let text = rand!(55);

    b.iter(|| {
        Ghash::new(&key).input_a(&aad).input_c(&text).result()
    });
}
