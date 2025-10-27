# Foundry Setup for SimplexVerifier

## Prerequisites

You need to install [Foundry](https://book.getfoundry.sh/) to compile and test the Solidity contracts.

## Installation

### 1. Install Foundry

```bash
# Install foundryup
curl -L https://foundry.paradigm.xyz | bash

# Follow the instructions, then run:
foundryup
```

This installs:
- `forge` - Ethereum testing framework
- `cast` - Swiss army knife for interacting with contracts
- `anvil` - Local Ethereum node
- `chisel` - Solidity REPL

### 2. Install Dependencies

```bash
cd contracts

# Install forge-std (testing library)
forge install foundry-rs/forge-std --no-commit
```

This creates a `lib/` directory with the forge-std library.

### 3. Verify Installation

```bash
# Check forge is installed
forge --version

# Build contracts
forge build

# Run tests
forge test -vvv
```

## Project Structure

```
contracts/
├── foundry.toml           # Foundry configuration
├── src/
│   └── SimplexVerifier.sol  # Main contract
├── test/
│   └── SimplexVerifier.t.sol  # Test suite
└── lib/                   # Dependencies (auto-generated)
    └── forge-std/         # Foundry testing library
```

## Common Commands

### Building

```bash
# Build all contracts
forge build

# Build with gas reporting
forge build --sizes
```

### Testing

```bash
# Run all tests
forge test

# Run with verbose output
forge test -vvv

# Run specific test
forge test --match-test testDeserializeNotarize -vvv

# Run with gas reporting
forge test --gas-report
```

### Formatting

```bash
# Check formatting
forge fmt --check

# Auto-format
forge fmt
```

## Troubleshooting

### Error: "Source forge-std/Test.sol not found"

**Cause:** Dependencies not installed.

**Fix:**
```bash
cd contracts
forge install foundry-rs/forge-std --no-commit
```

### Error: "command not found: forge"

**Cause:** Foundry not installed or not in PATH.

**Fix:**
```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Restart your shell or run:
source ~/.zshrc  # or ~/.bashrc
```

### Error: Compiler warnings

Enable strict mode to catch all warnings:
```bash
forge build --force
```

## IDE Integration

### VS Code

Install the [Solidity extension](https://marketplace.visualstudio.com/items?itemName=JuanBlanco.solidity):

```bash
code --install-extension JuanBlanco.solidity
```

Configure in `.vscode/settings.json`:
```json
{
  "solidity.compileUsingRemoteVersion": "0.8.19",
  "solidity.formatter": "forge",
  "solidity.remappings": [
    "forge-std/=lib/forge-std/src/"
  ]
}
```

### Other IDEs

- **Remix:** Copy contracts to [Remix IDE](https://remix.ethereum.org/)
- **Hardhat:** Compatible, but requires configuration changes

## Manual Dependency Installation (if forge install fails)

If `forge install` doesn't work, manually clone the dependency:

```bash
cd contracts
mkdir -p lib
cd lib
git clone https://github.com/foundry-rs/forge-std.git
cd ..
```

Then verify with `forge build`.

## Alternative: Using Git Submodules

If you prefer git submodules over Foundry's installer:

```bash
cd contracts
git submodule add https://github.com/foundry-rs/forge-std.git lib/forge-std
git submodule update --init --recursive
```

## Next Steps

Once setup is complete:

1. ✅ Build contracts: `forge build`
2. ✅ Run tests: `forge test -vvv`
3. ✅ Check gas usage: `forge test --gas-report`
4. ✅ Generate Rust integration proofs: `cd .. && cargo test --test simplex_solidity_proofs -- --nocapture`

## Resources

- [Foundry Book](https://book.getfoundry.sh/)
- [Forge Standard Library](https://github.com/foundry-rs/forge-std)
- [Solidity Documentation](https://docs.soliditylang.org/)
