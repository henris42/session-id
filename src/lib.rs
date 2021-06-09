
//use std::sync::*;
//use std::cell::*;
//use std::rc::*;

use hmac::Hmac;
//use log::*;
use rand::{thread_rng, Rng};
use sha2::Sha256;
use percent_encoding::*;

pub struct State {
    secret: Vec<u8>,
    salt: Vec<u8>,
    step: usize,
    rounds: usize,
}


pub struct SessionId {
    session: Box<State>,
}
impl SessionId {
    pub fn new(rounds: usize, salt: Vec<u8>) -> SessionId {
        let mut array = [0_u8; 32];
        thread_rng().fill(&mut array);
        let s = Box::new(State {
                secret: array.to_vec(),
                salt: salt,
                step: 0,
                rounds: rounds,
            });

        SessionId {
            session: s,
        }
    }

    pub fn get(&self) -> Vec<u8> {
        let mut v = [0_u8; 32];
        pbkdf2::pbkdf2::<Hmac<Sha256>>(
            &self.session.secret,
            &self.session.salt,
	    (self.session.rounds + self.session.step) as u32,
            &mut v,
        );
        v.to_vec()
    }

    pub fn get_b64(&self) -> String {
        let v = self.get();
        let b64 = base64::encode(&v);
        let sess = percent_encode(b64.clone().as_bytes(), NON_ALPHANUMERIC).to_string();
        sess
    }

    pub fn next(&mut self) {
        self.session.step = self.session.step + 1;
        //&self
    }

    pub fn get_secret(&self) -> Vec<u8> {
        self.session.secret.to_vec()
    }

    pub fn get_secret_b64(&self) -> String {
        let v = self.get_secret();
        let b64 = base64::encode(&v);
        b64
    }

    pub fn set_secret(&mut self, secret: Vec<u8>) {
        self.session.secret = secret;
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        simple_logger::init().unwrap();
        let salt = hex::decode("aaccee0022446688aaccee0022446688").unwrap();
        let mut s = super::SessionId::new(1000, salt);

        let ss = hex::decode("aaccee0022446688aaccee0022446688").unwrap();
        s.set_secret(ss.to_vec());

        log::info!("r1= {:x?}", &s.get());
        log::info!("r1= {:x?}", &s.get());
        s.next();
        log::info!("r1= {:x?}", &s.get());
        log::info!("r1= {:x?}", &s.get());
        s.next();
        log::info!("r1= {:x?}", &s.get());
        log::info!("r1= {}", &s.get_b64());

        assert_eq!(2 + 2, 4);
    }
}
