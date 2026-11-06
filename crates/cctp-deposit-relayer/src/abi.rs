use alloy_sol_types::sol;
sol! {
    interface Helper {
        function receiveAndDeposit(bytes message, bytes attestation) external;
        function messageTransmitter() external view returns (address);
        function tokenMessenger() external view returns (address);
    }
    interface Transmitter {
        event MessageSent(bytes message);
        function usedNonces(bytes32 nonce) external view returns (uint256);
    }
}

#[cfg(test)]
mod release_tests {
    use super::Helper;
    use alloy_primitives::keccak256;
    use alloy_sol_types::SolCall;

    #[test]
    fn worker_interface_matches_compiler_generated_helper_abi() {
        let abi: serde_json::Value = serde_json::from_str(include_str!(
            "../../../contracts/cctp-deposit-helper/abi/MidenCctpDepositHelper.json"
        ))
        .unwrap();
        for (name, signature, selector) in [
            (
                "receiveAndDeposit",
                "receiveAndDeposit(bytes,bytes)",
                Helper::receiveAndDepositCall::SELECTOR,
            ),
            (
                "messageTransmitter",
                "messageTransmitter()",
                Helper::messageTransmitterCall::SELECTOR,
            ),
            (
                "tokenMessenger",
                "tokenMessenger()",
                Helper::tokenMessengerCall::SELECTOR,
            ),
        ] {
            let matches: Vec<_> = abi
                .as_array()
                .unwrap()
                .iter()
                .filter(|item| item["type"] == "function" && item["name"] == name)
                .collect();
            assert_eq!(matches.len(), 1);
            let inputs = matches[0]["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|input| input["type"].as_str().unwrap())
                .collect::<Vec<_>>()
                .join(",");
            assert_eq!(format!("{name}({inputs})"), signature);
            assert_eq!(&keccak256(signature.as_bytes())[..4], selector);
            assert_eq!(
                matches[0]["stateMutability"],
                if inputs.is_empty() {
                    "view"
                } else {
                    "nonpayable"
                }
            );
            if inputs.is_empty() {
                assert_eq!(matches[0]["outputs"][0]["type"], "address");
            }
        }
    }
}
