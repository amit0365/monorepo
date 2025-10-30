how would digest abstraction work? look at bls sol file metioned
mcopy - this is a Solidity version issue with BLS library
hashToG1 method missing - BLS
Write tests for message encoding conformance
think signature verfication for each scheme
check correclntess of contracts first then optimize for gas (not a priority as fraud proofs are not invoked often and there is a bigger bounty to catch jsut make sure gas doesnt blow up. mostly gas is used in hash + signature verfication)
check solidty types we input and return view, calldata/memory etc
check solidty if need to return full length struct or just the fields we need - optmisstion