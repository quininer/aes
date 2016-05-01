use ::state::{ State, Ops, create_state };
use ::cipher::{ SingleBlockEncrypt, SingleBlockDecrypt };


lazy_static!{
    pub static ref SBOX: [u8; 256] = {
        fn lrot8(x: u8, shift: u8) -> u8 { (x << shift) | (x >> (8 - shift)) }

        let mut sbox = [0; 256];
        let mut p: u8 = 1;
        let mut q: u8 = 1;

        loop {
            p = p ^ (p << 1) ^ (if p & 0x80 == 0 { 0x00 } else { 0x1b });
            q ^= q << 1;
            q ^= q << 2;
            q ^= q << 4;
            q ^= if q & 0x80 == 0 { 0x00 } else { 0x09 };
            sbox[p as usize] = 0x63 ^ q ^ lrot8(q, 1) ^ lrot8(q, 2) ^ lrot8(q, 3) ^ lrot8(q, 4);
            if p == 1 { break };
        }

        sbox[0] = 0x63;
        sbox
    };

    pub static ref RSBOX: [u8; 256] = {
        let mut rsbox = [0; 256];

        for (i, &j) in SBOX.iter().enumerate() {
            rsbox[j as usize] = i as u8;
        }

        rsbox
    };

    /// Only the first some of these constants are actually used – up to `rcon[10]` for AES-128 (as 11 round keys are needed).
    /// `rcon[0]` is not used in AES algorithm.
    pub static ref RCON: [u8; 10] = {
        fn rcon(mut x: u8) -> u8 {
            let mut c = 1;
            if x == 0 { return 0x8d };
            while x != 1 {
                let b = c & 0x80;
                c <<= 1;
                if b == 0x80 { c ^= 0x1b };
                x -= 1;
            }
            c
        }

        let mut rconbox = [0; 10];
        for i in 1..11 {
            rconbox[i-1] = rcon(i as u8);
        }
        rconbox
    };
}


/// ```
/// use aes::aes::key_expansion;
/// let mut output = [[[0; 4]; 4]; 11];
/// key_expansion(&[0; 16], &mut output);
/// assert_eq!(output, [
///     [[0x00, 0x00, 0x00, 0x00], [0x00, 0x00, 0x00, 0x00], [0x00, 0x00, 0x00, 0x00], [0x00, 0x00, 0x00, 0x00]],
///     [[0x62, 0x63, 0x63, 0x63], [0x62, 0x63, 0x63, 0x63], [0x62, 0x63, 0x63, 0x63], [0x62, 0x63, 0x63, 0x63]],
///     [[0x9b, 0x98, 0x98, 0xc9], [0xf9, 0xfb, 0xfb, 0xaa], [0x9b, 0x98, 0x98, 0xc9], [0xf9, 0xfb, 0xfb, 0xaa]],
///     [[0x90, 0x97, 0x34, 0x50], [0x69, 0x6c, 0xcf, 0xfa], [0xf2, 0xf4, 0x57, 0x33], [0x0b, 0x0f, 0xac, 0x99]],
///     [[0xee, 0x06, 0xda, 0x7b], [0x87, 0x6a, 0x15, 0x81], [0x75, 0x9e, 0x42, 0xb2], [0x7e, 0x91, 0xee, 0x2b]],
///     [[0x7f, 0x2e, 0x2b, 0x88], [0xf8, 0x44, 0x3e, 0x09], [0x8d, 0xda, 0x7c, 0xbb], [0xf3, 0x4b, 0x92, 0x90]],
///     [[0xec, 0x61, 0x4b, 0x85], [0x14, 0x25, 0x75, 0x8c], [0x99, 0xff, 0x09, 0x37], [0x6a, 0xb4, 0x9b, 0xa7]],
///     [[0x21, 0x75, 0x17, 0x87], [0x35, 0x50, 0x62, 0x0b], [0xac, 0xaf, 0x6b, 0x3c], [0xc6, 0x1b, 0xf0, 0x9b]],
///     [[0x0e, 0xf9, 0x03, 0x33], [0x3b, 0xa9, 0x61, 0x38], [0x97, 0x06, 0x0a, 0x04], [0x51, 0x1d, 0xfa, 0x9f]],
///     [[0xb1, 0xd4, 0xd8, 0xe2], [0x8a, 0x7d, 0xb9, 0xda], [0x1d, 0x7b, 0xb3, 0xde], [0x4c, 0x66, 0x49, 0x41]],
///     [[0xb4, 0xef, 0x5b, 0xcb], [0x3e, 0x92, 0xe2, 0x11], [0x23, 0xe9, 0x51, 0xcf], [0x6f, 0x8f, 0x18, 0x8e]]
/// ]);
///
/// let mut output = [[[0; 4]; 4]; 15];
/// key_expansion(&[
///     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
///     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
/// ], &mut output);
/// assert_eq!(output, [
///     [[0x00, 0x01, 0x02, 0x03], [0x04, 0x05, 0x06, 0x07], [0x08, 0x09, 0x0a, 0x0b], [0x0c, 0x0d, 0x0e, 0x0f]],
///     [[0x10, 0x11, 0x12, 0x13], [0x14, 0x15, 0x16, 0x17], [0x18, 0x19, 0x1a, 0x1b], [0x1c, 0x1d, 0x1e, 0x1f]],
///     [[0xa5, 0x73, 0xc2, 0x9f], [0xa1, 0x76, 0xc4, 0x98], [0xa9, 0x7f, 0xce, 0x93], [0xa5, 0x72, 0xc0, 0x9c]],
///     [[0x16, 0x51, 0xa8, 0xcd], [0x02, 0x44, 0xbe, 0xda], [0x1a, 0x5d, 0xa4, 0xc1], [0x06, 0x40, 0xba, 0xde]],
///     [[0xae, 0x87, 0xdf, 0xf0], [0x0f, 0xf1, 0x1b, 0x68], [0xa6, 0x8e, 0xd5, 0xfb], [0x03, 0xfc, 0x15, 0x67]],
///     [[0x6d, 0xe1, 0xf1, 0x48], [0x6f, 0xa5, 0x4f, 0x92], [0x75, 0xf8, 0xeb, 0x53], [0x73, 0xb8, 0x51, 0x8d]],
///     [[0xc6, 0x56, 0x82, 0x7f], [0xc9, 0xa7, 0x99, 0x17], [0x6f, 0x29, 0x4c, 0xec], [0x6c, 0xd5, 0x59, 0x8b]],
///     [[0x3d, 0xe2, 0x3a, 0x75], [0x52, 0x47, 0x75, 0xe7], [0x27, 0xbf, 0x9e, 0xb4], [0x54, 0x07, 0xcf, 0x39]],
///     [[0x0b, 0xdc, 0x90, 0x5f], [0xc2, 0x7b, 0x09, 0x48], [0xad, 0x52, 0x45, 0xa4], [0xc1, 0x87, 0x1c, 0x2f]],
///     [[0x45, 0xf5, 0xa6, 0x60], [0x17, 0xb2, 0xd3, 0x87], [0x30, 0x0d, 0x4d, 0x33], [0x64, 0x0a, 0x82, 0x0a]],
///     [[0x7c, 0xcf, 0xf7, 0x1c], [0xbe, 0xb4, 0xfe, 0x54], [0x13, 0xe6, 0xbb, 0xf0], [0xd2, 0x61, 0xa7, 0xdf]],
///     [[0xf0, 0x1a, 0xfa, 0xfe], [0xe7, 0xa8, 0x29, 0x79], [0xd7, 0xa5, 0x64, 0x4a], [0xb3, 0xaf, 0xe6, 0x40]],
///     [[0x25, 0x41, 0xfe, 0x71], [0x9b, 0xf5, 0x00, 0x25], [0x88, 0x13, 0xbb, 0xd5], [0x5a, 0x72, 0x1c, 0x0a]],
///     [[0x4e, 0x5a, 0x66, 0x99], [0xa9, 0xf2, 0x4f, 0xe0], [0x7e, 0x57, 0x2b, 0xaa], [0xcd, 0xf8, 0xcd, 0xea]],
///     [[0x24, 0xfc, 0x79, 0xcc], [0xbf, 0x09, 0x79, 0xe9], [0x37, 0x1a, 0xc2, 0x3c], [0x6d, 0x68, 0xde, 0x36]]
/// ]);
/// ```
pub fn key_expansion(key: &[u8], round_keys: &mut [State]) {
    let key_words = key.len() / 4;
    debug_assert!(match key_words { 4 | 6 | 8 => true, _ => false });
    let rounds = 10 + key_words - 4;

    for (i, j) in (0..key.len()).step_by(4).enumerate() {
        for n in 0..4 {
            round_keys[i / 4][i % 4][j % 4 + n] = key[j + n];
        }
    }

    for i in key_words..(rounds + 1) * 4 {
        let mut tmp = round_keys[(i-1) / 4][(i-1) % 4];
        if i % key_words == 0 {
            tmp = tmp.lrot().sub_sbox();
            tmp[0] ^= RCON[i / key_words - 1];
        } else if key_words > 6 && i % key_words == 4 {
            tmp = tmp.sub_sbox();
        };
        round_keys[i / 4][i % 4] =
            round_keys[(i-key_words) / 4][(i-key_words) % 4].xor(&tmp);
    }
}


fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0;
    for _ in 0..8 {
        if b & 1 != 0 { p ^= a };
        let hi_bit_set = a & 0x80;
        a <<= 1;
        if hi_bit_set != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

macro_rules! impl_mix_columns {
    ( $name:ident, $mult0:expr, $mult1:expr, $mult2:expr, $mult3:expr ) => {
        pub fn $name(state: &State) -> State {
            let mut out = state.clone();
            for i in 0..4 {
                out[i][0] = gmul($mult0, state[i][0])
                    ^ gmul($mult3, state[i][1])
                    ^ gmul($mult2, state[i][2])
                    ^ gmul($mult1, state[i][3]);
                out[i][1] = gmul($mult1, state[i][0])
                    ^ gmul($mult0, state[i][1])
                    ^ gmul($mult3, state[i][2])
                    ^ gmul($mult2, state[i][3]);
                out[i][2] = gmul($mult2, state[i][0])
                    ^ gmul($mult1, state[i][1])
                    ^ gmul($mult0, state[i][2])
                    ^ gmul($mult3, state[i][3]);
                out[i][3] = gmul($mult3, state[i][0])
                    ^ gmul($mult2, state[i][1])
                    ^ gmul($mult1, state[i][2])
                    ^ gmul($mult0, state[i][3]);
            }
            out
        }
    }
}

pub fn add_round_key(state: &State, round_key: &State) -> State { state.xor(round_key) }
pub fn sub_bytes(state: &State) -> State { state.sub_sbox() }
pub fn inv_sub_bytes(state: &State) -> State { state.sub_rsbox() }
pub fn shift_rows(state: &State) -> State { reversal(&reversal(&state).lrot()) }
pub fn inv_shift_rows(state: &State) -> State { reversal(&reversal(&state).rrot()) }
impl_mix_columns!(mix_columns, 0x02, 0x01, 0x01, 0x03);
impl_mix_columns!(inv_mix_columns, 0x0e, 0x09, 0x0d, 0x0b);

/// ```
/// use aes::aes::reversal;
/// assert_eq!(
///     reversal(&[
///         [0, 1, 2, 3],
///         [4, 5, 6, 7],
///         [8, 9, 1, 2],
///         [3, 4, 5, 6]
///     ]),
///     [
///         [0, 4, 8, 3],
///         [1, 5, 9, 4],
///         [2, 6, 1, 5],
///         [3, 7, 2, 6]
///     ]
/// );
/// ```
pub fn reversal(input: &State) -> State {
    let mut out = [[0; 4]; 4];
    for (i, &n) in input.iter().enumerate() {
        for (j, &u) in n.iter().enumerate() {
            out[j][i] = u;
        }
    }
    out
}

pub fn encrypt_core(round_keys: &[State], data: &[u8]) -> Vec<u8> {
    let rounds = round_keys.len() - 1;
    let mut state = create_state(data);
    state = add_round_key(&state, &round_keys[0]);

    for i in 1..rounds {
        state = sub_bytes(&state);
        state = shift_rows(&state);
        state = mix_columns(&state);
        state = add_round_key(&state, &round_keys[i]);
    }

    state = sub_bytes(&state);
    state = shift_rows(&state);
    state = add_round_key(&state, &round_keys[rounds]);

    state.concat()
}

pub fn decrypt_core(round_keys: &[State], data: &[u8]) -> Vec<u8> {
    let rounds = round_keys.len() - 1;
    let mut state = create_state(data);
    state = add_round_key(&state, &round_keys[rounds]);

    for i in (1..rounds).rev() {
        state = inv_shift_rows(&state);
        state = inv_sub_bytes(&state);
        state = add_round_key(&state, &round_keys[i]);
        state = inv_mix_columns(&state);
    }

    state = inv_sub_bytes(&state);
    state = inv_shift_rows(&state);
    state = add_round_key(&state, &round_keys[0]);

    state.concat()
}

#[derive(Clone)]
pub struct AES {
    round_keys: Vec<State>
}

impl AES {
    pub fn new(key: &[u8]) -> AES {
        let rounds = 10 + (key.len() / 4) - 4;
        let mut round_keys = vec![[[0; 4]; 4]; rounds + 1];
        key_expansion(key, &mut round_keys);

        AES { round_keys: round_keys }
    }
}

impl SingleBlockEncrypt for AES {
    fn bs() -> usize { 16 }

    /// ```
    /// use aes::AES;
    /// use aes::cipher::SingleBlockEncrypt;
    /// assert_eq!(
    ///     AES::new(b"0123456789123456").encrypt(b"0987654321123456"),
    ///     [215, 88, 51, 56, 75, 78, 81, 214, 230, 55, 134, 27, 39, 58, 179, 70]
    /// );
    /// ```
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        encrypt_core(&self.round_keys, data)
    }
}

impl SingleBlockDecrypt for AES {
    fn bs() -> usize { 16 }

    /// ```
    /// use aes::AES;
    /// use aes::cipher::{ SingleBlockEncrypt, SingleBlockDecrypt };
    /// assert_eq!(
    ///     AES::new(b"0123456789123456").decrypt(&AES::new(b"0123456789123456").encrypt(b"0987654321123456")),
    ///     b"0987654321123456"
    /// );
    /// assert_eq!(
    ///     AES::new(b"0123456789123456").encrypt(&AES::new(b"0123456789123456").decrypt(b"0987654321123456")),
    ///     b"0987654321123456"
    /// );
    /// ```
    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        decrypt_core(&self.round_keys, data)
    }
}
