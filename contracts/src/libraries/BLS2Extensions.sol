// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BLS2} from "bls-solidity/libraries/BLS2.sol";

/// @title BLS2Extensions
/// @notice Extensions to the BLS2 library for operations not included in bls-solidity
/// @dev Provides G2 point addition needed for BLS multisig aggregation
library BLS2Extensions {
    // ============ Constants ============

    /// @notice EIP-2537 BLS12-381 G2 point addition precompile address
    uint256 constant BLS12_G2ADD = 0x0c;

    // ============ Errors ============

    error G2AddFailed();

    // ============ G2 Operations ============

    /// @notice Add two G2 points using EIP-2537 precompile
    /// @param a First G2 point
    /// @param b Second G2 point
    /// @return result Sum of a and b on G2
    function g2Add(BLS2.PointG2 memory a, BLS2.PointG2 memory b)
        internal
        view
        returns (BLS2.PointG2 memory result)
    {
        // Input format for BLS12_G2ADD precompile (384 bytes):
        // First point (192 bytes) + Second point (192 bytes)
        uint256[48] memory input;

        // Pack first point (a)
        input[0] = a.x1_hi;
        input[1] = a.x1_lo;
        input[2] = a.x0_hi;
        input[3] = a.x0_lo;
        input[4] = a.y1_hi;
        input[5] = a.y1_lo;
        input[6] = a.y0_hi;
        input[7] = a.y0_lo;

        // Pack second point (b)
        input[8] = b.x1_hi;
        input[9] = b.x1_lo;
        input[10] = b.x0_hi;
        input[11] = b.x0_lo;
        input[12] = b.y1_hi;
        input[13] = b.y1_lo;
        input[14] = b.y0_hi;
        input[15] = b.y0_lo;

        bool success;
        assembly {
            // Call BLS12_G2ADD precompile
            // Input: 384 bytes (two G2 points)
            // Output: 192 bytes (one G2 point)
            success := staticcall(
                gas(),
                BLS12_G2ADD,
                input,
                384,  // 48 * 32 / 4 = 384 bytes
                result,
                192   // 24 * 32 / 4 = 192 bytes
            )
        }

        if (!success) revert G2AddFailed();
    }
}
