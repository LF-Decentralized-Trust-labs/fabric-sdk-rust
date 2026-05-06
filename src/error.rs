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
