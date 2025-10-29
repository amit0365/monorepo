Updated Architecture
// ============ Scheme Interface with Public Key Management ============

interface IAttributableScheme {
    function SCHEME_ID() external pure returns (string memory);
    function HASH_FUNCTION() external view returns (HashFunction);
    
    // Public key management
    function getPublicKey(uint32 signerIndex) external view returns (bytes memory);
    function participantCount() external view returns (uint32);
    
    // Deserialize certificate (format differs by scheme!)
    function deserializeCertificate(
        bytes calldata proof,
        uint256 offset,
        uint32 maxSigners
    ) external pure returns (
        uint32[] memory signers,
        bytes[] memory signatures,
        uint256 newOffset
    );
    
    // Hash + verify (scheme handles hash choice + crypto)
    function hashAndVerify(
        bytes calldata message,
        uint32[] calldata signers,
        bytes[] calldata signatures
    ) external view returns (bool);
}

interface IAggregatedScheme {
    function SCHEME_ID() external pure returns (string memory);
    function HASH_FUNCTION() external view returns (HashFunction);
    
    // Public key management
    function getPublicKey(uint32 signerIndex) external view returns (bytes memory);
    function participantCount() external view returns (uint32);
    
    // Deserialize certificate (different format: bitmap + single sig)
    function deserializeCertificate(
        bytes calldata proof,
        uint256 offset,
        uint32 maxSigners
    ) external pure returns (
        bytes memory signersBitmap,
        bytes memory signature,
        uint256 newOffset
    );
    
    // Hash + verify aggregated
    function hashAndVerify(
        bytes calldata message,
        bytes calldata signersBitmap,
        bytes calldata signature
    ) external view returns (bool);
}

interface IThresholdScheme {
    function SCHEME_ID() external pure returns (string memory);
    function HASH_FUNCTION() external view returns (HashFunction);
    
    // Public key management (single threshold key)
    function getThresholdPublicKey() external view returns (bytes memory);
    function participantCount() external view returns (uint32);
    
    // Deserialize certificate (just signature, no signer info)
    function deserializeCertificate(
        bytes calldata proof,
        uint256 offset
    ) external pure returns (
        bytes memory signature,
        uint256 newOffset
    );
    
    // Hash + verify threshold
    function hashAndVerify(
        bytes calldata message,
        bytes calldata signature
    ) external view returns (bool);
}
Implementation Examples
Ed25519 Scheme (Attributable)
contract Ed25519Scheme is IAttributableScheme {
    bytes32[] public publicKeys;  // Scheme owns the keys!
    HashFunction public immutable hashFunction;
    
    constructor(bytes32[] memory _publicKeys, HashFunction _hashFunction) {
        require(_publicKeys.length > 0, "Need at least one key");
        publicKeys = _publicKeys;
        hashFunction = _hashFunction;
    }
    
    function SCHEME_ID() external pure returns (string memory) {
        return "ED25519";
    }
    
    function HASH_FUNCTION() external view returns (HashFunction) {
        return hashFunction;
    }
    
    // ============ Public Key Management ============
    
    function getPublicKey(uint32 signerIndex) external view returns (bytes memory) {
        require(signerIndex < publicKeys.length, "Invalid signer index");
        return abi.encodePacked(publicKeys[signerIndex]);
    }
    
    function participantCount() external view returns (uint32) {
        return uint32(publicKeys.length);
    }
    
    // ============ Certificate Deserialization ============
    
    function deserializeCertificate(
        bytes calldata proof,
        uint256 offset,
        uint32 maxSigners
    ) external pure returns (
        uint32[] memory signers,
        bytes[] memory signatures,
        uint256 newOffset
    ) {
        // Read bitmap
        uint64 bitmapLengthInBits;
        bytes memory signersBitmap;
        (bitmapLengthInBits, signersBitmap, offset) = 
            _deserializeSignersBitmap(proof, offset, maxSigners);
        
        // Read signatures
        (signers, signatures, offset) = 
            _deserializeSignatures(proof, offset, signersBitmap, maxSigners);
        
        return (signers, signatures, offset);
    }
    
    // ============ Verification ============
    
    function hashAndVerify(
        bytes calldata message,
        uint32[] calldata signers,
        bytes[] calldata signatures
    ) external view returns (bool) {
        require(signers.length == signatures.length, "Length mismatch");
        
        // Hash the message
        bytes32 messageHash = _hash(message);
        
        // Verify each signature against corresponding public key
        for (uint i = 0; i < signers.length; i++) {
            uint32 signerIndex = signers[i];
            require(signerIndex < publicKeys.length, "Invalid signer");
            
            if (!_verifyEd25519(messageHash, publicKeys[signerIndex], signatures[i])) {
                return false;
            }
        }
        
        return true;
    }
    
    // ============ Internal Helpers ============
    
    function _hash(bytes memory data) internal view returns (bytes32) {
        if (hashFunction == HashFunction.SHA256) return sha256(data);
        if (hashFunction == HashFunction.BLAKE2B) return _blake2b(data);
        if (hashFunction == HashFunction.KECCAK256) return keccak256(data);
        revert("Unknown hash function");
    }
    
    function _verifyEd25519(
        bytes32 messageHash,
        bytes32 publicKey,
        bytes memory signature
    ) internal pure returns (bool) {
        // Ed25519 verification implementation
        // Could use precompile or library
    }
    
    function _deserializeSignersBitmap(...) internal pure returns (...) {
        // Implementation from SimplexVerifierEd25519
    }
    
    function _deserializeSignatures(...) internal pure returns (...) {
        // Implementation from SimplexVerifierEd25519
    }
}
BLS Multisig Scheme (Aggregated)
import {BLS2} from "./libraries/BLS2.sol";

contract BLSMultisigScheme is IAggregatedScheme {
    BLS2.PointG2[] public publicKeys;  // Scheme owns BLS keys!
    HashFunction public immutable hashFunction;
    bytes public DST;  // Domain separation tag
    
    constructor(
        bytes[] memory publicKeyBytes,
        HashFunction _hashFunction,
        string memory application
    ) {
        require(publicKeyBytes.length > 0, "Need at least one key");
        
        publicKeys = new BLS2.PointG2[](publicKeyBytes.length);
        for (uint i = 0; i < publicKeyBytes.length; i++) {
            publicKeys[i] = BLS2.g2Unmarshal(publicKeyBytes[i]);
        }
        
        hashFunction = _hashFunction;
        DST = abi.encodePacked(
            application,
            "-BLS12381G1_XMD:SHA-256_SSWU_RO_",
            _bytes32ToHex(bytes32(block.chainid)),
            "_"
        );
    }
    
    function SCHEME_ID() external pure returns (string memory) {
        return "BLS12381_MULTISIG";
    }
    
    function HASH_FUNCTION() external view returns (HashFunction) {
        return hashFunction;
    }
    
    // ============ Public Key Management ============
    
    function getPublicKey(uint32 signerIndex) external view returns (bytes memory) {
        require(signerIndex < publicKeys.length, "Invalid signer index");
        return BLS2.g2Marshal(publicKeys[signerIndex]);
    }
    
    function participantCount() external view returns (uint32) {
        return uint32(publicKeys.length);
    }
    
    // ============ Certificate Deserialization ============
    
    function deserializeCertificate(
        bytes calldata proof,
        uint256 offset,
        uint32 maxSigners
    ) external pure returns (
        bytes memory signersBitmap,
        bytes memory signature,
        uint256 newOffset
    ) {
        // Read bitmap
        uint64 bitmapLengthInBits;
        (bitmapLengthInBits, signersBitmap, offset) = 
            _deserializeSignersBitmap(proof, offset, maxSigners);
        
        // Read single aggregated signature (96 bytes for BLS)
        require(offset + 96 <= proof.length, "Invalid proof length");
        signature = proof[offset:offset+96];
        offset += 96;
        
        return (signersBitmap, signature, offset);
    }
    
    // ============ Verification ============
    
    function hashAndVerify(
        bytes calldata message,
        bytes calldata signersBitmap,
        bytes calldata signature
    ) external view returns (bool) {
        // Hash the message
        bytes32 messageHash = _hash(message);
        
        // Hash to BLS point
        BLS2.PointG1 memory messagePoint = BLS2.hashToG1(messageHash, DST);
        
        // Aggregate public keys for signers in bitmap
        BLS2.PointG2 memory aggregatedPubKey = _aggregatePublicKeys(signersBitmap);
        
        // Verify aggregated signature
        BLS2.PointG1 memory sig = BLS2.g1Unmarshal(signature);
        return BLS2.pairing(messagePoint, aggregatedPubKey, sig);
    }
    
    // ============ Internal Helpers ============
    
    function _aggregatePublicKeys(bytes memory bitmap) 
        internal view returns (BLS2.PointG2 memory) 
    {
        BLS2.PointG2 memory result;
        bool first = true;
        
        for (uint32 i = 0; i < publicKeys.length; i++) {
            if (_getBit(bitmap, i)) {
                if (first) {
                    result = publicKeys[i];
                    first = false;
                } else {
                    result = BLS2.g2Add(result, publicKeys[i]);
                }
            }
        }
        
        require(!first, "No signers in bitmap");
        return result;
    }
    
    function _hash(bytes memory data) internal view returns (bytes32) {
        if (hashFunction == HashFunction.SHA256) return sha256(data);
        if (hashFunction == HashFunction.BLAKE2B) return _blake2b(data);
        if (hashFunction == HashFunction.KECCAK256) return keccak256(data);
        revert("Unknown hash function");
    }
    
    function _getBit(bytes memory bitmap, uint256 index) internal pure returns (bool) {
        uint256 byteIndex = index >> 3;
        uint256 bitIndex = index & 7;
        if (byteIndex >= bitmap.length) return false;
        return (uint8(bitmap[byteIndex]) & (1 << bitIndex)) != 0;
    }
}
BLS Threshold Scheme
contract BLSThresholdScheme is IThresholdScheme {
    BLS2.PointG2 public thresholdPublicKey;  // Single threshold key!
    uint32 public immutable n;  // Total participants
    HashFunction public immutable hashFunction;
    bytes public DST;
    
    constructor(
        bytes memory thresholdKeyBytes,
        uint32 _n,
        HashFunction _hashFunction,
        string memory application
    ) {
        require(_n > 0, "Need at least one participant");
        thresholdPublicKey = BLS2.g2Unmarshal(thresholdKeyBytes);
        n = _n;
        hashFunction = _hashFunction;
        DST = abi.encodePacked(
            application,
            "-BLS12381G1_XMD:SHA-256_SSWU_RO_",
            _bytes32ToHex(bytes32(block.chainid)),
            "_"
        );
    }
    
    function SCHEME_ID() external pure returns (string memory) {
        return "BLS12381_THRESHOLD";
    }
    
    function HASH_FUNCTION() external view returns (HashFunction) {
        return hashFunction;
    }
    
    // ============ Public Key Management ============
    
    function getThresholdPublicKey() external view returns (bytes memory) {
        return BLS2.g2Marshal(thresholdPublicKey);
    }
    
    function participantCount() external view returns (uint32) {
        return n;
    }
    
    // ============ Certificate Deserialization ============
    
    function deserializeCertificate(
        bytes calldata proof,
        uint256 offset
    ) external pure returns (
        bytes memory signature,
        uint256 newOffset
    ) {
        // Just read signature (96 bytes for BLS)
        require(offset + 96 <= proof.length, "Invalid proof length");
        signature = proof[offset:offset+96];
        return (signature, offset + 96);
    }
    
    // ============ Verification ============
    
    function hashAndVerify(
        bytes calldata message,
        bytes calldata signature
    ) external view returns (bool) {
        // Hash the message
        bytes32 messageHash = _hash(message);
        
        // Hash to BLS point
        BLS2.PointG1 memory messagePoint = BLS2.hashToG1(messageHash, DST);
        
        // Verify threshold signature against threshold public key
        BLS2.PointG1 memory sig = BLS2.g1Unmarshal(signature);
        return BLS2.pairing(messagePoint, thresholdPublicKey, sig);
    }
    
    function _hash(bytes memory data) internal view returns (bytes32) {
        if (hashFunction == HashFunction.SHA256) return sha256(data);
        if (hashFunction == HashFunction.BLAKE2B) return _blake2b(data);
        if (hashFunction == HashFunction.KECCAK256) return keccak256(data);
        revert("Unknown hash function");
    }
}
Summary: What Each Component Owns
SimplexVerifierBase (Consensus Protocol)
✅ Round, Proposal structs
✅ Deserialize consensus structures
✅ Build messages (universal format)
✅ Varint helpers
Signature Schemes (Cryptography)
✅ Public key storage & management ← Added!
✅ Certificate deserialization (format differs)
✅ Hash function choice
✅ Signature verification
Verifiers (Orchestration)
✅ Call Base for consensus structures
✅ Call Scheme for certificates
✅ Call Base for messages
✅ Call Scheme for verification
Now each scheme completely owns its cryptographic concerns including public key management! Does this complete the architecture?

