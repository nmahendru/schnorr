//!
//!
//!
//! Implementing the schnorr signature for fun
//! # https://en.wikipedia.org/wiki/Schnorr_signature
//!
use curv::BigInt;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use curv::elliptic::curves::secp256_k1::{Secp256k1Scalar, Secp256k1Point};
use curv::arithmetic::traits::*;
use sha2::{Sha256, Digest};
fn hash_func(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().as_slice().into()
}
pub fn sign_schnorr(x: &Secp256k1Scalar, m: &[u8]) -> (Secp256k1Scalar, Secp256k1Scalar){
    let k = Secp256k1Scalar::new_random();
    let r = Secp256k1Point::generator().scalar_mul(&k.get_element());
    let mut r_bytes  = r.pk_to_key_slice();
    r_bytes.extend(m.iter());
    let e: Secp256k1Scalar = ECScalar::from(&BigInt::from_bytes(hash_func(r_bytes.as_slice()).as_slice()));
    let s = k.sub(&(*x * e).get_element());
    (s, e)
}

pub fn verify_schnorr(p: &Secp256k1Point, m: &[u8], s: &(Secp256k1Scalar, Secp256k1Scalar)) -> bool {
    let rv = Secp256k1Point::generator().scalar_mul(&s.0.get_element()).add_point(&p.scalar_mul(&s.1.get_element()).get_element());
    let mut rv_bytes = rv.pk_to_key_slice();
    rv_bytes.extend(m.iter());
    let ev: Secp256k1Scalar = ECScalar::from(&BigInt::from_bytes(hash_func(rv_bytes.as_slice()).as_slice()));
    ev == s.1
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sign(){
        let x = Secp256k1Scalar::new_random();
        let m = &[1,1,1,1];
        let sig  = sign_schnorr(&x, m);
        let p = Secp256k1Point::generator().scalar_mul(&x.get_element());
        assert!(verify_schnorr(&p, m, &sig));
    }
}
