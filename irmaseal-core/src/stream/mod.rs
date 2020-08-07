//! Implementation of the IRMAseal stream format. Includes zero-allocation streaming encryption and decryption.

mod opener;
mod sealer;
pub(crate) mod util;

#[cfg(test)]
mod tests;

use ctr::stream_cipher::{NewStreamCipher, StreamCipher};
use wasm_bindgen::{prelude::*, JsValue};
use wasm_bindgen_futures::JsFuture;
use js_sys::{Uint8Array, Map, Array};
use web_sys::{AesCtrParams, SubtleCrypto, CryptoKey};
use async_std::task;

pub use opener::OpenerSealed;
// TODO: Distinguish implementation based on build type or determine dynamically.
pub type OpenerUnsealed<R> = opener::OpenerUnsealed<R, SoftwareSymCrypt>;
pub type Sealer<'a, W> = sealer::Sealer<'a, W, SoftwareSymCrypt>;

//TODO: Find way to prevent SymCrypt to become public
pub trait SymCrypt {
    fn new(
        key: &[u8; KEYSIZE],
        nonce: &[u8; IVSIZE]
    ) -> Self;
    fn encrypt(&mut self, data: &mut [u8]);
    fn decrypt(&mut self, data: &mut [u8]);
}

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

pub struct SoftwareSymCrypt {
    aes: Aes
}

impl SymCrypt for SoftwareSymCrypt {
    fn new(key: &[u8; KEYSIZE], nonce: &[u8; IVSIZE]) -> Self {
        let aes = Aes::new(key.into(), nonce.into());
        SoftwareSymCrypt { aes }
    }

    fn encrypt(&mut self, data: &mut [u8]) {
        self.aes.encrypt(data)
    }

    fn decrypt(&mut self, data: &mut [u8]) {
        self.aes.decrypt(data)
    }
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn get_subtle_crypto() -> SubtleCrypto;
}

pub struct WasmSymCrypt {
    key: CryptoKey,
    current_nonce: Uint8Array,
}

impl SymCrypt for WasmSymCrypt {
    fn new(key: &[u8; KEYSIZE], nonce: &[u8; IVSIZE]) -> Self {
        task::block_on(async {
            let subtle_crypto = get_subtle_crypto();
            let algorithm = Map::new();
            algorithm.set(&JsValue::from_str("name"), &JsValue::from_str("AES-CTR"));
            let key_usages = Array::of2(&JsValue::from_str("encrypt"), &JsValue::from_str("decrypt"));
            let key_value: Uint8Array = key.as_ref().into();
            let key_promise = subtle_crypto.import_key_with_object("raw", &key_value.into(), &algorithm.into(), false, &key_usages);
            let key_object = JsFuture::from(key_promise.unwrap()).await.unwrap();
            WasmSymCrypt { key: key_object.into(), current_nonce: nonce.as_ref().into() }
        })
    }

    fn encrypt(&mut self, data: &mut [u8]) {
        task::block_on(async {
            let params = AesCtrParams::new("AES-CTR", &self.current_nonce, 128);
            let subtle_crypto = get_subtle_crypto();
            let result = subtle_crypto.encrypt_with_object_and_u8_array(&params, &self.key, data);
            let encrypted: Uint8Array = JsFuture::from(result.unwrap()).await.unwrap().into();
            encrypted.copy_to(data);
        })
    }

    fn decrypt(&mut self, data: &mut [u8]) {
        task::block_on(async {
            let params = AesCtrParams::new("AES-CTR", &self.current_nonce, 128);
            let subtle_crypto = get_subtle_crypto();
            let result = subtle_crypto.decrypt_with_object_and_u8_array(&params, &self.key, data);
            let encrypted: Uint8Array = JsFuture::from(result.unwrap()).await.unwrap().into();
            encrypted.copy_to(data);
        })
    }
}
