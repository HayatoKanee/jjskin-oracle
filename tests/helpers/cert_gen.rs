//! Generate ephemeral test certificates with custom SANs for Steam hosts.
//!
//! Uses `rcgen` to create a CA cert + server cert at test runtime.
//! The server cert covers both api.steampowered.com and steamcommunity.com.

use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
};

pub struct TestCerts {
    pub ca_cert_der: Vec<u8>,
    pub server_cert_der: Vec<u8>,
    pub server_key_der: Vec<u8>,
}

pub fn generate_test_certs() -> TestCerts {
    // 1. Generate CA key pair + self-signed CA cert
    let ca_key = KeyPair::generate().expect("CA key generation failed");

    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Test CA");
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];

    let ca_cert = ca_params
        .self_signed(&ca_key)
        .expect("CA cert self-sign failed");

    // 2. Generate server key pair + cert signed by CA
    let server_key = KeyPair::generate().expect("Server key generation failed");

    let mut server_params = CertificateParams::new(vec![
        "api.steampowered.com".to_string(),
        "steamcommunity.com".to_string(),
        "127.0.0.1".to_string(),
    ])
    .unwrap();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "api.steampowered.com");

    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("Server cert signing failed");

    TestCerts {
        ca_cert_der: ca_cert.der().to_vec(),
        server_cert_der: server_cert.der().to_vec(),
        server_key_der: server_key.serialize_der(),
    }
}
