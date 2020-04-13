use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Create {
    pub id: String,
    pub nonce: Option<String>,
    pub channel: String,
    pub author: String,
    pub content: String,
}