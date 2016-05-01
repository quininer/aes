#![feature(step_by)]

#[macro_use] extern crate lazy_static;

pub mod state;
pub mod aes;
pub mod cipher;

pub use aes::AES;
