use crate::stream::*;

use ctr::stream_cipher::{NewStreamCipher, StreamCipher};

pub struct SymCrypt {
    aes: Aes
}

impl SymCrypt {
    pub async fn new(key: &[u8; KEYSIZE], nonce: &[u8; IVSIZE]) -> Self {
        let aes = Aes::new(key.into(), nonce.into());
        SymCrypt { aes }
    }

    pub async fn encrypt(&mut self, data: &mut [u8]) {
        self.aes.encrypt(data)
    }

    pub async fn decrypt(&mut self, data: &mut [u8]) {
        self.aes.decrypt(data)
    }
}
