use ::aes::{ SBOX, RSBOX };


#[allow(non_camel_case_types)]
pub type u8x4 = [u8; 4];
pub type State = [u8x4; 4];

/// ```
/// use aes::state::create_state;
/// assert_eq!(
///     create_state(&[[1, 2, 3, 4]; 4].concat()),
///     [[1, 2, 3, 4]; 4]
/// );
/// ```
pub fn create_state(input: &[u8]) -> State {
    assert_eq!(input.len(), 16);
    let mut state = [[0; 4]; 4];
    for (i, &j) in input.iter().enumerate() {
        state[i / 4][i % 4] = j;
    }
    state

}

pub trait Ops {
    fn lrot(&self) -> Self;
    fn rrot(&self) -> Self;
    fn xor(&self, rhs: &Self) -> Self;
    fn sub_sbox(&self) -> Self;
    fn sub_rsbox(&self) -> Self;
}

impl Ops for u8x4 {
    /// ```
    /// use aes::state::Ops;
    /// assert_eq!(
    ///     [1, 2, 3, 4].lrot(),
    ///     [2, 3, 4, 1]
    /// );
    /// assert_eq!(
    ///     [0x1d, 0x2c, 0x3a, 0x4f].lrot(),
    ///     [0x2c, 0x3a, 0x4f, 0x1d]
    /// );
    /// ```
    fn lrot(&self) -> Self {
        [self[1], self[2], self[3], self[0]]
    }

    /// ```
    /// use aes::state::Ops;
    /// assert_eq!(
    ///     [1, 2, 3, 4].rrot(),
    ///     [4, 1, 2, 3]
    /// );
    /// assert_eq!(
    ///     [1, 2, 3, 4].rrot().lrot(),
    ///     [1, 2, 3, 4]
    /// );
    /// ```
    fn rrot(&self) -> Self {
        [self[3], self[0], self[1], self[2]]
    }

    /// ```
    /// use aes::state::Ops;
    /// assert_eq!(
    ///     [1, 2, 3, 4].xor(&[4, 3, 2, 1]),
    ///     [5, 1, 1, 5]
    /// );
    /// ```
    fn xor(&self, rhs: &Self) -> Self {
        [
            self[0] ^ rhs[0],
            self[1] ^ rhs[1],
            self[2] ^ rhs[2],
            self[3] ^ rhs[3]
        ]
    }

    /// ```
    /// use aes::state::Ops;
    /// assert_eq!(
    ///     [1, 2, 3, 4].sub_sbox(),
    ///     [0x7c, 0x77, 0x7b, 0xf2]
    /// );
    /// ```
    fn sub_sbox(&self) -> Self {
        [
            SBOX[self[0] as usize],
            SBOX[self[1] as usize],
            SBOX[self[2] as usize],
            SBOX[self[3] as usize]
        ]
    }

    /// ```
    /// use aes::state::Ops;
    /// assert_eq!(
    ///     [1, 2, 3, 4].sub_sbox().sub_rsbox(),
    ///     [1, 2, 3, 4]
    /// );
    /// ```
    fn sub_rsbox(&self) -> Self {
        [
            RSBOX[self[0] as usize],
            RSBOX[self[1] as usize],
            RSBOX[self[2] as usize],
            RSBOX[self[3] as usize]
        ]
    }
}

impl Ops for State {
    /// ```
    /// use aes::state::Ops;
    /// assert_eq!(
    ///     [[1, 2, 3, 4]; 4].lrot(),
    ///     [
    ///         [1, 2, 3, 4],
    ///         [2, 3, 4, 1],
    ///         [3, 4, 1, 2],
    ///         [4, 1, 2, 3]
    ///     ]
    /// );
    /// ```
    fn lrot(&self) -> Self {
        [
            self[0],
            self[1].lrot(),
            self[2].lrot().lrot(),
            self[3].lrot().lrot().lrot(),
        ]
    }

    /// ```
    /// use aes::state::Ops;
    /// assert_eq!(
    ///     [[1, 2, 3, 4]; 4].lrot().rrot(),
    ///     [[1, 2, 3, 4]; 4]
    /// );
    /// ```
    fn rrot(&self) -> Self {
        [
            self[0],
            self[1].rrot(),
            self[2].rrot().rrot(),
            self[3].rrot().rrot().rrot()
        ]
    }

    /// ```
    /// use aes::state::Ops;
    /// assert_eq!(
    ///     [[1, 2, 3, 4]; 4].xor(&[[4, 3, 2, 1]; 4]),
    ///     [[5, 1, 1, 5]; 4]
    /// );
    /// ```
    fn xor(&self, rhs: &Self) -> Self {
        [
            self[0].xor(&rhs[0]),
            self[1].xor(&rhs[1]),
            self[2].xor(&rhs[2]),
            self[3].xor(&rhs[3]),
        ]
    }

    /// ```
    /// use aes::state::Ops;
    /// assert_eq!(
    ///     [[1, 2, 3, 4]; 4].sub_sbox(),
    ///     [[124, 119, 123, 242]; 4]
    /// );
    /// ```
    fn sub_sbox(&self) -> Self {
        [
            self[0].sub_sbox(),
            self[1].sub_sbox(),
            self[2].sub_sbox(),
            self[3].sub_sbox()
        ]
    }

    /// ```
    /// use aes::state::Ops;
    /// assert_eq!(
    ///     [[1, 2, 3, 4]; 4].sub_sbox().sub_rsbox(),
    ///     [[1, 2, 3, 4]; 4]
    /// );
    /// ```
    fn sub_rsbox(&self) -> Self {
        [
            self[0].sub_rsbox(),
            self[1].sub_rsbox(),
            self[2].sub_rsbox(),
            self[3].sub_rsbox()
        ]
    }
}
