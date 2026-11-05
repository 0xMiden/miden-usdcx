/**
 * Copyright 2025 Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
pragma solidity ^0.8.29;

import {TransferSpec} from "src/lib/TransferSpec.sol";

// Magic values for marking byte encodings
bytes4 constant ATTESTATION_MAGIC = 0xff6fb334; // `bytes4(keccak256("circle.gateway.Attestation"))`
bytes4 constant ATTESTATION_SET_MAGIC = 0x1e12db71; // `bytes4(keccak256("circle.gateway.AttestationSet"))`

// `Attestation` field offsets
uint16 constant ATTESTATION_MAGIC_OFFSET = 0;
uint16 constant ATTESTATION_MAX_BLOCK_HEIGHT_OFFSET = 4;
uint16 constant ATTESTATION_TRANSFER_SPEC_LENGTH_OFFSET = 36;
uint16 constant ATTESTATION_TRANSFER_SPEC_OFFSET = 40;

// `AttestationSet` field offsets
uint16 constant ATTESTATION_SET_MAGIC_OFFSET = 0;
uint16 constant ATTESTATION_SET_NUM_ATTESTATIONS_OFFSET = 4;
uint16 constant ATTESTATION_SET_ATTESTATIONS_OFFSET = 8;

/// @title Attestation
///
/// @notice Passed to the `GatewayMinter` contract on the destination domain by the user or a relayer
///
/// @dev Magic: `bytes4(keccak256("circle.gateway.Attestation"))`
/// @dev The `keccak256` hash of the encoded `TransferSpec` is used as a cross-chain identifier, for both linkability
///      and replay protection. See `TransferSpecHashes.sol` for more details.
///
/// @dev Byte encoding (big-endian):
///     FIELD                      OFFSET   BYTES   NOTES
///     magic                           0       4   Always 0xff6fb334
///     max block height                4      32
///     transfer spec length           36       4   In bytes, may vary based on hook data length
///     encoded transfer spec          40       ?   Must be the length indicated above
struct Attestation {
    uint256 maxBlockHeight; //   Valid until this block height
    TransferSpec spec; //        A description of the transfer
}

/// @title AttestationSet
///
/// @notice Represents multiple `Attestation`s packed together, for transferring from multiple domains
///
/// @dev Magic: bytes4(keccak256("circle.gateway.AttestationSet"))
///
/// @dev Byte encoding (big-endian):
///     FIELD                      OFFSET   BYTES   NOTES
///     magic                           0       4   Always 0x1e12db71
///     number of attestations          4       4
///     attestations                    8       ?   Concatenated one after another
struct AttestationSet {
    Attestation[] attestations;
}
