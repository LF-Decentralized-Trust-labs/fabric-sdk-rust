use crate::client::{Client, Contract};

#[derive(Clone)]
pub struct Network {
    client: Client,
    channel_name: String,
}

impl Network {
    fn get_contract(&self, contract_name: String) -> Contract {
        Contract {
            network: self.clone(),
            contract_name,
        }
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn channel_name(&self) -> &str {
        &self.channel_name
    }
}