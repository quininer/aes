use num::{ BigUint, Zero, One };


#[derive(Clone, Debug)]
pub struct Ghash {
    key: BigUint,
    state: BigUint,
    buffer: Vec<u8>,
    aad_len: BigUint,
    txt_len: usize
}

impl Ghash {
    pub fn new(key: &[u8], aad: &[u8]) -> Ghash {
        let mut ghash = Ghash {
            key: BigUint::from_bytes_be(key),
            state: BigUint::zero(),
            buffer: Vec::with_capacity(15),
            aad_len: BigUint::from(aad.len() * 8) << 64,
            txt_len: 0
        };
        ghash.update(&[
            aad,
            &vec![0; (16 - aad.len() % 16) % 16]
        ].concat());
        ghash
    }

    // TODO Pre tablet
    fn xor_mult(&self, p: &BigUint, q: &BigUint) -> BigUint {
        gmult(&self.key, &(p ^ q))
    }

    fn update(&mut self, data: &[u8]) {
        let mut buffer = self.buffer.clone();
        buffer.extend_from_slice(data);
        let pos = buffer.len() / 16 * 16;
        let (head, tail) = buffer.split_at(pos);
        for b in head.chunks(16).map(BigUint::from_bytes_be) {
            self.state = self.xor_mult(&self.state, &b);
        }
        self.buffer = tail.into();
    }

    pub fn input(&mut self, data: &[u8]) -> Ghash {
        self.update(data);
        self.txt_len += data.len();
        self.clone()
    }

    pub fn result(&self) -> Vec<u8> {
        let state = if self.buffer.is_empty() {
            self.state.clone()
        } else {
            self.xor_mult(&self.state, &BigUint::from_bytes_be(&[
                self.buffer.clone(),
                vec![0; (16 - self.buffer.len() % 16) % 16]
            ].concat()))
        };

        let out = self.xor_mult(
            &state,
            &(&self.aad_len | BigUint::from(self.txt_len * 8))
        ).to_bytes_be();

        [
            vec![0; 16 - out.len()],
            out
        ].concat()
    }
}


pub fn gmult(x: &BigUint, y: &BigUint) -> BigUint {
    let one = BigUint::one();
    let e1 = BigUint::from(0xe1u32) << 120;

    let mut out = BigUint::zero();
    let mut x = x.clone();
    for i in (0..128).rev() {
        out = out ^ (&x * ((y >> i) & &one));
        x = (&x >> 1) ^ ((&x & &one) * &e1);
    }
    out
}
