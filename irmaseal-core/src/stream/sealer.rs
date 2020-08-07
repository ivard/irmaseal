use hmac::Mac;
use rand::{CryptoRng, Rng};

use crate::stream::*;
use crate::*;

//TODO: Function is re-exported, so find way to make it private or pub(crate) somehow.
/// Sealer for an bytestream, which converts it into an IRMAseal encrypted bytestream.
pub struct Sealer<'a, W: Writable, S: SymCrypt> {
    aes: S,
    hmac: Verifier,
    w: &'a mut W,
}

impl<'a, W: Writable, S: SymCrypt> Sealer<'a, W, S> {
    pub fn new<R: Rng + CryptoRng>(
        i: &Identity,
        pk: &PublicKey,
        rng: &mut R,
        w: &'a mut W,
    ) -> Result<Sealer<'a, W, S>, Error> {
        let (c, k) = ibe::kiltz_vahlis_one::encrypt(&pk.0, &i.derive(), rng);

        let (aeskey, mackey) = crate::stream::util::derive_keys(&k);
        let iv = crate::stream::util::generate_iv(rng);

        let aes = S::new(&aeskey.into(), &iv.into());
        let mut hmac = Verifier::new_varkey(&mackey).unwrap();

        let ciphertext = c.to_bytes();

        hmac.input(&PRELUDE);
        w.write(&PRELUDE)?;

        hmac.input(&[FORMAT_VERSION]);
        w.write(&[FORMAT_VERSION])?;

        i.write_to(&mut hmac)?;
        i.write_to(w)?;

        hmac.input(&ciphertext);
        w.write(&ciphertext)?;

        hmac.input(&iv);
        w.write(&iv)?;

        Ok(Sealer { aes, hmac, w })
    }
}

impl Writable for Verifier {
    fn write(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.input(buf);
        Ok(())
    }
}

impl<'a, W: Writable, S: SymCrypt> Writable for Sealer<'a, W, S> {
    fn write(&mut self, buf: &[u8]) -> Result<(), Error> {
        let mut tmp = [0u8; BLOCKSIZE];

        for c in buf.chunks(BLOCKSIZE) {
            let subtmp = &mut tmp[0..c.len()];
            subtmp.copy_from_slice(c);
            self.aes.encrypt(subtmp);
            self.hmac.input(subtmp);
            self.w.write(subtmp)?;
        }

        Ok(())
    }
}

impl<'a, W: Writable, S: SymCrypt> Drop for Sealer<'a, W, S> {
    fn drop(&mut self) {
        let code = self.hmac.result_reset().code();
        self.w.write(&code).unwrap()
    }
}
