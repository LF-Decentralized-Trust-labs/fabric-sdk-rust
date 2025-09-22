use std::{env, fs};
use tonic::transport::{Certificate, Channel, ClientTlsConfig};

async fn handshake_orderer() -> Channel {
    let tls_path =
        env::var("ORDERER_TLS_CERT_PATH").expect("TLS_CERT_PATH environment variable not set");
    println!("Path: {}", tls_path);

    let cert = Certificate::from_pem(fs::read(tls_path).expect("Couldn't read file"));

    let tls_config = ClientTlsConfig::new().ca_certificate(cert.clone());

    let channel: Channel = Channel::from_static("https://localhost:7050")
        .tls_config(tls_config)
        .expect("Invalid TLS config")
        .connect()
        .await
        .unwrap();
    channel
}

async fn handshake_peer1() -> Channel {
    let tls_path =
        env::var("PEER1_TLS_CERT_PATH").expect("TLS_CERT_PATH environment variable not set");

    let cert = Certificate::from_pem(fs::read(tls_path).expect("Couldn't read file"));

    let tls_config = ClientTlsConfig::new().ca_certificate(cert.clone());

    let channel: Channel = Channel::from_static("https://localhost:7051")
        .tls_config(tls_config)
        .expect("Invalid TLS config")
        .connect()
        .await
        .unwrap();
    channel
}

async fn handshake_peer2() -> Channel {
    let tls_path =
        env::var("PEER2_TLS_CERT_PATH").expect("TLS_CERT_PATH environment variable not set");

    let cert = Certificate::from_pem(fs::read(tls_path).expect("Couldn't read file"));

    let tls_config = ClientTlsConfig::new().ca_certificate(cert.clone());

    let channel: Channel = Channel::from_static("https://localhost:9051")
        .tls_config(tls_config)
        .expect("Invalid TLS config")
        .connect()
        .await
        .unwrap();
    channel
}

#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;
    use std::sync::Once;

    lazy_static! {
        static ref INITIALIZER: Once = Once::new();
    }

    fn initialize() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");
    }

    #[test]
    fn test_handshake_orderer() {
        dotenv::dotenv().unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                INITIALIZER.call_once(initialize);
                let connection = handshake_orderer().await;
                println!("{:?}", connection);
            });
    }

    #[test]
    fn test_handshake_peer0() {
        dotenv::dotenv().unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                INITIALIZER.call_once(initialize);
                let connection = handshake_peer1().await;
                println!("{:?}", connection);
            });
    }

    #[test]
    fn test_handshake_peer1() {
        dotenv::dotenv().unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                INITIALIZER.call_once(initialize);
                let connection = handshake_peer2().await;
                println!("{:?}", connection);
            });
    }
}
