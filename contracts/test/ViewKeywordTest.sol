// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract ViewKeywordTest {
    // Test if 'view' can be used as a struct field name
    struct Round {
        uint64 epoch;
        uint64 viewCounter;  // Does this compile?
    }

    function test() public pure returns (Round memory) {
        Round memory r = Round({
            epoch: 1,
            viewCounter: 100
        });

        // Can we access it? Yes, this line compiles successfully
        uint64 _v = r.viewCounter;

        return r;
    }
}
