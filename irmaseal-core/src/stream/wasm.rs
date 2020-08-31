use crate::stream::*;

use wasm_bindgen::{prelude::*, JsValue};
use wasm_bindgen_futures::JsFuture;
use js_sys::{Uint8Array, Array, Object, Reflect};
use web_sys::{AesCtrParams, SubtleCrypto, CryptoKey};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = crypto)]
    fn get_subtle_crypto() -> SubtleCrypto;
}

pub struct SymCrypt {
    key: CryptoKey,
    current_nonce: Uint8Array,
}

impl SymCrypt {
    pub async fn new(key: &[u8; KEYSIZE], nonce: &[u8; IVSIZE]) -> Self {
        let subtle_crypto = get_subtle_crypto();
        let algorithm: JsValue = Object::new().into();
        Reflect::set(&algorithm, &JsValue::from_str("name"), &JsValue::from_str("AES-CTR")).unwrap();
        let key_usages = Array::of2(&JsValue::from_str("encrypt"), &JsValue::from_str("decrypt"));
        let key_value: Uint8Array = key.as_ref().into();
        let key_promise = subtle_crypto.import_key_with_object("raw", &key_value.into(), &algorithm.into(), false, &key_usages);
        let key_object = JsFuture::from(key_promise.unwrap()).await.unwrap();
        SymCrypt { key: key_object.into(), current_nonce: nonce.as_ref().into() }
    }

    pub async fn encrypt(&mut self, data: &mut [u8]) {
        let params = AesCtrParams::new("AES-CTR", &self.current_nonce, 128);
        let subtle_crypto = get_subtle_crypto();
        let result = subtle_crypto.encrypt_with_object_and_u8_array(&params, &self.key, data);
        let encrypted: Uint8Array = JsFuture::from(result.unwrap()).await.unwrap().into();
        encrypted.copy_to(data);
    }

    pub async fn decrypt(&mut self, data: &mut [u8]) {
        let params = AesCtrParams::new("AES-CTR", &self.current_nonce, 128);
        let subtle_crypto = get_subtle_crypto();
        let result = subtle_crypto.decrypt_with_object_and_u8_array(&params, &self.key, data);
        let encrypted: Uint8Array = JsFuture::from(result.unwrap()).await.unwrap().into();
        encrypted.copy_to(data);
    }
}
