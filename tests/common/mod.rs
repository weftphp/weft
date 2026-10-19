//! Shared helpers for integration tests.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{SslConnector, SslMethod, SslStream};
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, SubjectAlternativeName};
use openssl::x509::{X509, X509NameBuilder};

/// A throwaway CA and a certificate it signs for `localhost` and `127.0.0.1`, as PEM files
/// in a temporary directory that is removed on drop.
pub struct Pki {
    pub dir: PathBuf,
    pub ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn new_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

fn sign(name: &str, key: &PKey<Private>, issuer: Option<(&X509, &PKey<Private>)>) -> X509 {
    let mut subject = X509NameBuilder::new().unwrap();
    subject.append_entry_by_text("CN", name).unwrap();
    let subject = subject.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    let mut serial = [0u8; 4];
    openssl::rand::rand_bytes(&mut serial).unwrap();
    let serial = BigNum::from_u32(u32::from_be_bytes(serial) >> 1).unwrap();
    b.set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(&subject).unwrap();
    b.set_pubkey(key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(2).unwrap())
        .unwrap();
    match issuer {
        None => {
            b.set_issuer_name(&subject).unwrap();
            b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
            b.sign(key, MessageDigest::sha256()).unwrap();
        }
        Some((ca, ca_key)) => {
            b.set_issuer_name(ca.subject_name()).unwrap();
            let san = SubjectAlternativeName::new()
                .dns("localhost")
                .ip("127.0.0.1")
                .build(&b.x509v3_context(Some(ca), None))
                .unwrap();
            b.append_extension(san).unwrap();
            b.append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
                .unwrap();
            b.sign(ca_key, MessageDigest::sha256()).unwrap();
        }
    }
    b.build()
}

pub fn pki() -> Pki {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "weft-it-pki-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let ca_key = new_key();
    let ca = sign("weft integration CA", &ca_key, None);
    let key = new_key();
    let cert = sign("localhost", &key, Some((&ca, &ca_key)));
    let write = |name: &str, pem: Vec<u8>| {
        let path = dir.join(name);
        std::fs::write(&path, pem).unwrap();
        path
    };
    Pki {
        ca: write("ca.pem", ca.to_pem().unwrap()),
        cert: write("cert.pem", cert.to_pem().unwrap()),
        key: write("key.pem", key.private_key_to_pem_pkcs8().unwrap()),
        dir,
    }
}

/// A blocking, verifying TLS client over `stream` for `localhost`, offering `alpn`.
pub fn tls_client<S: Read + Write + std::fmt::Debug>(
    pki: &Pki,
    stream: S,
    alpn: &[&str],
) -> SslStream<S> {
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_ca_file(&pki.ca).unwrap();
    if !alpn.is_empty() {
        let mut wire = Vec::new();
        for p in alpn {
            wire.push(p.len() as u8);
            wire.extend_from_slice(p.as_bytes());
        }
        builder.set_alpn_protos(&wire).unwrap();
    }
    builder.build().connect("localhost", stream).unwrap()
}
