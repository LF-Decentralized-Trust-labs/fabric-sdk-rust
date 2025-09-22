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
            },
        }
    }
}
