pub mod state;
pub mod padding;
pub mod ghash;


pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter())
        .map(|(x, &y)| x ^ y)
        .collect()
}
