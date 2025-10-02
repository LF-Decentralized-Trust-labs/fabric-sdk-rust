use std::str::FromStr;

use crate::{error::BuilderError, signer::Signer, transaction::TransaktionBuilder};

pub struct Client {
    identity: crate::protos::msp::SerializedIdentity,
    signer: Signer,
    tonic_connection: TonicConnection,
}

struct TonicConnection {
    tls_config: tonic::transport::ClientTlsConfig,
    host: tonic::transport::Uri,
    channel: Option<tonic::transport::Channel>,
}

impl Client {
    pub async fn connect(&mut self) -> Result<(), tonic::transport::Error> {
        self.tonic_connection.channel = Some(
            tonic::transport::Channel::builder(self.tonic_connection.host.clone())
                .tls_config(self.tonic_connection.tls_config.clone())
                .expect("Invald TLS config")
                .connect()
                .await?,
        );
        Ok(())
    }
    /// A builder for creating `PreparedTransaction` instances, from which you can submit the transaction.
    /// build() only prepares the transaction. It will not send anything to the network.
    ///
    /// # Examples
    ///
    /// ```rust
    ///  let tx_builder = client
    ///    .get_transaction_builder()
    ///    .with_channel_name("mychannel")?
    ///    .with_chaincode_id("basic")?
    ///    .with_function_name("CreateAsset")?
    ///    .with_function_args(["assetCustom", "orange", "10", "Frank", "600"])?
    ///    .build();
    ///  match tx_builder {
    ///    Ok(prepared_transaction) => match prepared_transaction.submit().await {
    ///        Ok(result) => {
    ///            println!("{}", String::from_utf8_lossy(result.as_slice()));
    ///        }
    ///        Err(err) => println!("{}", err),
    ///    },
    ///    Err(err) => println!("{}", err),
    ///  }
    /// ```
    pub fn get_transaction_builder(&self) -> TransaktionBuilder {
        TransaktionBuilder {
            identity: self.identity.clone(),
            channel: self.tonic_connection.channel.clone().unwrap(),
            signer: self.signer.clone(),
            channel_name: None,
            chaincode_id: None,
            function_name: None,
            function_args: vec![],
        }
    }
}

/// The `ClientBuilder` struct is used to configure and build a `Client` instance. It provides methods to set various parameters required for creating a client, such as identity, signer, TLS configuration, scheme, and authority.
///
/// # Examples
///
/// ```rust
/// use fabric_sdk_rust::{client::ClientBuilder, identity::IdentityBuilder, signer::Signer};
///
/// let identity = IdentityBuilder::from_pem(std::fs::read(msp_signcert_path)?.as_slice())
///    .with_msp("Org1MSP")?
///    .build()?;
/// let mut client = ClientBuilder::new()
///    .with_identity(identity)?
///    .with_tls(std::fs::read(tls_cert_path)?)?
///    .with_signer(Signer::new(std::fs::read(keystore_path)?))?
///    .build()?;
/// client.connect().await?;
/// ```
#[derive(Default)]
pub struct ClientBuilder {
    identity: Option<crate::protos::msp::SerializedIdentity>,
    tls: Option<Vec<u8>>,
    signer: Option<Signer>,
    scheme: Option<String>,
    authority: Option<String>,
}

impl ClientBuilder {
    pub fn new() -> ClientBuilder {
        ClientBuilder::default()
    }

    pub fn with_identity(
        mut self,
        identity: crate::protos::msp::SerializedIdentity,
    ) -> Result<ClientBuilder, BuilderError> {
        self.identity = Some(identity);
        Ok(self)
    }

    pub fn with_signer(mut self, signer: Signer) -> Result<ClientBuilder, BuilderError> {
        self.signer = Some(signer);
        Ok(self)
    }

    pub fn with_sheme(mut self, scheme: impl Into<String>) -> Result<ClientBuilder, BuilderError> {
        let scheme = scheme.into().trim().to_string();
        if scheme.is_empty() {
            return Err(BuilderError::InvalidParameter(
                "scheme cannot be empty".into(),
            ));
        }
        self.scheme = Some(scheme);
        Ok(self)
    }

    pub fn with_tls(mut self, bytes: impl Into<Vec<u8>>) -> Result<ClientBuilder, BuilderError> {
        self.tls = Some(bytes.into());
        Ok(self)
    }

    pub fn with_authority(
        mut self,
        authority: impl Into<String>,
    ) -> Result<ClientBuilder, BuilderError> {
        let authority = authority.into().trim().to_string();
        if authority.is_empty() {
            return Err(BuilderError::InvalidParameter(
                "authority cannot be empty".into(),
            ));
        }
        self.authority = Some(authority);
        Ok(self)
    }

    pub fn build(self) -> Result<Client, BuilderError> {
        let identity = match self.identity {
            Some(identity) => identity,
            None => return Err(BuilderError::MissingParameter("identity".into())),
        };
        let signer = match self.signer {
            Some(signer) => signer,
            None => return Err(BuilderError::MissingParameter("signer".into())),
        };
        let tls = match self.tls {
            Some(tls) => tls,
            None => return Err(BuilderError::MissingParameter("tls".into())),
        };
        //TODO Allow custom tls config
        let tls_config = tonic::transport::ClientTlsConfig::new()
            .ca_certificate(tonic::transport::Certificate::from_pem(tls.as_slice()));
        let scheme = match self.scheme {
            Some(scheme) => scheme,
            None => "https".to_string(),
        };
        let authority = match self.authority {
            Some(authority) => authority,
            None => "localhost:7051".to_string(),
        };
        let scheme =
            tonic::codegen::http::uri::Scheme::from_str(scheme.as_str()).expect("Invalid scheme");
        let uri_builder = tonic::transport::Uri::builder()
            .scheme(scheme)
            .authority(authority)
            .path_and_query("/");
        let uri = match uri_builder.build() {
            Ok(uri) => uri,
            Err(err) => return Err(BuilderError::InvalidParameter(err.to_string())),
        };
        let tonic_connection = TonicConnection {
            tls_config,
            host: uri,
            channel: None,
        };
        Ok(Client {
            identity,
            signer,
            tonic_connection,
        })
    }
}
