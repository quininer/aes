extern crate rand;
extern crate num;
extern crate crypto;
extern crate aes;

#[path = "./rand.rs"]
#[macro_use] mod rand_macro;

use num::BigUint;
use crypto::ghash::Ghash as CryptoGhash;
use aes::utils::ghash::{ Ghash, gmult };


#[test]
fn test_gmult() {
    assert_eq!(
        gmult(&BigUint::from(0u32), &BigUint::from(0u32)),
        BigUint::from(0u32)
    );

    assert_eq!(
        gmult(&BigUint::from(123u32), &BigUint::from(321u32)),
        BigUint::from_bytes_be(&[65, 216, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 157, 134])
    );
}

#[test]
fn test_ghash() {
    let key = rand!(16);
    let aad = rand!(rand!(choose 15..55));
    let text = rand!(rand!(choose 15..55));

    assert_eq!(
        Ghash::new(&key, &aad).input(&text).result(),
        CryptoGhash::new(&key).input_a(&aad).input_c(&text).result()
    );
}
