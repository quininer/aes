pub mod state;
pub mod padding;
pub mod ghash;


pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    debug_assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter())
        .map(|(x, &y)| x ^ y)
        .collect()
}

pub fn eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false };

    let mut d = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }

    d == 0
}
