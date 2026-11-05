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

/// @title Cursor
///
/// @notice Used to iterate over a single burn intent or attestation or a set of the same in a uniform way
struct Cursor {
    /// The `TypedMemView` reference pointing to the start of the encoded single burn intent, attestation, or set
    bytes29 memView;
    /// The byte offset within the `memView` data where the next burn intent or attestation begins
    uint256 offset;
    /// The total number of elements contained within `memView`. Always 1 for a single burn intent or attestation.
    uint32 numElements;
    /// The 0-based index of the next burn intent or attestation
    uint32 index;
    /// A flag indicating whether iteration is complete (i.e., `index == numElements`)
    bool done;
}
