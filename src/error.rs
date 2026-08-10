#[derive(Debug)]
pub enum BuilderError {
    InvalidParameter(String),
    MissingParameter(String),
}

impl std::error::Error for BuilderError {}

impl std::fmt::Display for BuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuilderError::InvalidParameter(reason) => write!(f, "Invalid parameter: {}", reason),
            BuilderError::MissingParameter(parameter) => {
                write!(f, "Missing parameter: {}", parameter)
            }
        }
    }
}

#[derive(Debug)]
pub enum ContractError {
    MethodCall(String),
}

impl std::error::Error for ContractError {}

impl std::fmt::Display for ContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContractError::MethodCall(err) => {
                write!(f, "Method call error: {}", err)
            }
        }
    }
}

#[derive(Debug)]
pub enum LifecycleError {
    NotConnected,
    NodeError(String),
    DecodeError(&'static str),
    EmptyResponse,
    BuilderError(BuilderError),
    SubmitError(SubmitError),
}

impl std::error::Error for LifecycleError {}

impl std::fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LifecycleError::NotConnected => write!(
                f,
                "Trying to submit something to the network, while not being connected to it"
            ),
            LifecycleError::NodeError(err) => write!(f, "Node error: {}", err),
            LifecycleError::DecodeError(err) => write!(f, "Failed decoding struct: {}", err),
            LifecycleError::EmptyResponse => write!(f, "Received empty response from node"),
            LifecycleError::BuilderError(err) => write!(f, "Builder error: {}", err),
            LifecycleError::SubmitError(err) => write!(f, "Submit error: {}", err),
        }
    }
}

impl From<BuilderError> for LifecycleError {
    fn from(err: BuilderError) -> Self {
        LifecycleError::BuilderError(err)
    }
}

impl From<SubmitError> for LifecycleError {
    fn from(err: SubmitError) -> Self {
        LifecycleError::SubmitError(err)
    }
}

/// Errors returned by the channel-configuration helpers in
/// [`gateway::configtx`](crate::gateway::configtx).
#[derive(Debug)]
pub enum ConfigTxError {
    /// The named config (`"original"` or `"updated"`) has no `channel_group`.
    NoChannelGroup(&'static str),
    /// The original and updated configs are identical; there is nothing to update.
    NoDifferences,
    /// A protobuf payload could not be decoded into the expected type.
    DecodeError(&'static str),
    /// A group or value expected in the config tree was not found (e.g. no
    /// `Application` group, or an unknown org MSP ID).
    ElementNotFound(String),
    /// An element that was supposed to be added already exists.
    AlreadyExists(String),
    /// The channel uses a consensus type the helper cannot edit (e.g. not `etcdraft`).
    UnsupportedConsensusType(String),
}

impl std::error::Error for ConfigTxError {}

impl std::fmt::Display for ConfigTxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigTxError::NoChannelGroup(which) => {
                write!(f, "No channel group included for {} config", which)
            }
            ConfigTxError::NoDifferences => {
                write!(f, "No differences detected between original and updated config")
            }
            ConfigTxError::DecodeError(err) => write!(f, "Failed decoding struct: {}", err),
            ConfigTxError::ElementNotFound(name) => {
                write!(f, "Config element not found: {}", name)
            }
            ConfigTxError::AlreadyExists(name) => {
                write!(f, "Config element already exists: {}", name)
            }
            ConfigTxError::UnsupportedConsensusType(t) => {
                write!(f, "Unsupported consensus type: {}", t)
            }
        }
    }
}

/// Errors returned by the system-chaincode clients ([`CsccClient`](crate::gateway::cscc::CsccClient)
/// and [`QsccClient`](crate::gateway::qscc::QsccClient)).
#[derive(Debug)]
pub enum SystemChaincodeError {
    /// The peer returned a non-200 proposal response.
    NodeError(String),
    /// The proposal response payload could not be decoded into the expected type.
    DecodeError(&'static str),
    /// The peer returned a proposal response without a `response` field.
    EmptyResponse,
    /// Building the proposal failed.
    BuilderError(BuilderError),
    /// Sending the proposal to the peer failed.
    SubmitError(SubmitError),
}

impl std::error::Error for SystemChaincodeError {}

impl std::fmt::Display for SystemChaincodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SystemChaincodeError::NodeError(err) => write!(f, "Node error: {}", err),
            SystemChaincodeError::DecodeError(err) => write!(f, "Failed decoding struct: {}", err),
            SystemChaincodeError::EmptyResponse => write!(f, "Received empty response from node"),
            SystemChaincodeError::BuilderError(err) => write!(f, "Builder error: {}", err),
            SystemChaincodeError::SubmitError(err) => write!(f, "Submit error: {}", err),
        }
    }
}

impl From<BuilderError> for SystemChaincodeError {
    fn from(err: BuilderError) -> Self {
        SystemChaincodeError::BuilderError(err)
    }
}

impl From<SubmitError> for SystemChaincodeError {
    fn from(err: SubmitError) -> Self {
        SystemChaincodeError::SubmitError(err)
    }
}

#[derive(Debug)]
pub enum FabricCAError {
    NotConfigured,
    HttpError(String),
    ParseError(String),
    CAError(String),
}

impl std::error::Error for FabricCAError {}

impl std::fmt::Display for FabricCAError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FabricCAError::NotConfigured => write!(f, "Fabric CA client is not configured"),
            FabricCAError::HttpError(err) => write!(f, "HTTP error: {}", err),
            FabricCAError::ParseError(err) => write!(f, "Failed to parse CA response: {}", err),
            FabricCAError::CAError(err) => write!(f, "Fabric CA returned an error: {}", err),
        }
    }
}

/// Errors returned by the [`OsnadminClient`](crate::osnadmin::OsnadminClient).
#[derive(Debug)]
pub enum OsnadminError {
    /// Transport-level failure (connection, TLS, timeout).
    HttpError(String),
    /// The response body could not be parsed.
    ParseError(String),
    /// The orderer answered with a non-success HTTP status.
    ServerError { status: u16, message: String },
}

impl std::error::Error for OsnadminError {}

impl std::fmt::Display for OsnadminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OsnadminError::HttpError(err) => write!(f, "HTTP error: {}", err),
            OsnadminError::ParseError(err) => {
                write!(f, "Failed to parse osnadmin response: {}", err)
            }
            OsnadminError::ServerError { status, message } => {
                write!(f, "Orderer admin endpoint returned {}: {}", status, message)
            }
        }
    }
}

/// Errors returned by the [`OperationsClient`](crate::operations::OperationsClient).
#[derive(Debug)]
pub enum OperationsError {
    /// Transport-level failure (connection, TLS, timeout).
    HttpError(String),
    /// The response body could not be parsed.
    ParseError(String),
    /// The node answered with a non-success HTTP status.
    ServerError { status: u16, message: String },
}

impl std::error::Error for OperationsError {}

impl std::fmt::Display for OperationsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperationsError::HttpError(err) => write!(f, "HTTP error: {}", err),
            OperationsError::ParseError(err) => {
                write!(f, "Failed to parse operations response: {}", err)
            }
            OperationsError::ServerError { status, message } => {
                write!(f, "Operations endpoint returned {}: {}", status, message)
            }
        }
    }
}

#[derive(Debug)]
pub enum SubmitError {
    NotConnected,
    NodeError(String),
    DecodeError(&'static str),
    EmptyRespone,
    NoPayload,
}

impl std::error::Error for SubmitError {}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubmitError::NotConnected => {
                write!(
                    f,
                    "Trying to submit something to the network, while not being connected to it"
                )
            }
            SubmitError::NodeError(err) => {
                write!(f, "Submitting to node failed: {}", err)
            }
            SubmitError::DecodeError(err) => {
                write!(f, "Failed decoding struct: {}", err)
            }
            SubmitError::EmptyRespone => {
                write!(f, "Received empty response from node")
            }
            SubmitError::NoPayload => write!(f, "Answer didn't cointained any payload"),
        }
    }
}
