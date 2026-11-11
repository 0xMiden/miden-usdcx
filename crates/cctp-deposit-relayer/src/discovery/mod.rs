pub(crate) mod evm;
pub(crate) mod solana;
pub(crate) struct Page {
    pub cursor: serde_json::Value,
    pub transactions: Vec<crate::message::Candidate>,
}
