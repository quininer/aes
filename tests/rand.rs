#[macro_export]
macro_rules! rand {
    ( _ ) => { rand::random() };
    ( $len:expr ) => {{
        use rand::Rng;
        rand::thread_rng().gen_iter().take($len).collect::<Vec<u8>>()
    }};
    ( choose $range:expr, $num:expr ) => {
        rand::sample(&mut rand::thread_rng(), $range, $num)
    };
    ( choose $range:expr ) => {
        rand!(choose $range, 1)[0]
    };
}
