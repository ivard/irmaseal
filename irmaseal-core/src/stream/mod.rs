//! Implementation of the IRMAseal stream format. Includes zero-allocation streaming encryption and decryption.

mod opener;
mod sealer;
mod wasm;
//mod crypto;
pub(crate) mod util;

#[cfg(test)]
mod tests;

pub use opener::*;
pub use sealer::*;

pub(crate) use wasm::*;
//pub(crate) use crypto::*;

type Aes = ctr::Ctr128<aes::Aes256>;
pub(crate) type Verifier = hmac::Hmac<sha3::Sha3_256>;

/// The tag 'IRMASEAL' with which all IRMAseal bytestreams start.
pub(crate) const PRELUDE: [u8; 4] = [0x14, 0x8A, 0x8E, 0xA7];
pub(crate) const FORMAT_VERSION: u8 = 0x00;

pub(crate) const KEYSIZE: usize = 32;
pub(crate) const IVSIZE: usize = 16;
pub(crate) const MACSIZE: usize = 32;

/// The stack buffer size that `opener` and `sealer` will use to yield chunks of plaintext and ciphertext.
pub const BLOCKSIZE: usize = 512;
