#![feature(test)]

extern crate test;
extern crate rand;
extern crate openssl;
extern crate crypto;
extern crate aes;

#[path = "../tests/rand.rs"]
#[macro_use] mod rand_macro;

use test::Bencher;
use aes::utils::padding::{
    Padding,
    Pkcs7Padding,
    NoPadding
};


#[bench]
fn bench_pkcs7padding(b: &mut Bencher) {
    let text = rand!(55);
    b.iter(|| Pkcs7Padding::unpadding(&Pkcs7Padding::padding(&text, 16), 16));
}

#[bench]
fn bench_nopadding(b: &mut Bencher) {
    let text = rand!(55);
    b.iter(|| NoPadding::unpadding(&NoPadding::padding(&text, 16), 16));
}
