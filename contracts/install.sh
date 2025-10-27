#!/bin/bash
set -e

echo "Setting up Foundry dependencies for SimplexVerifier..."

# Check if forge is installed
if ! command -v forge &> /dev/null; then
    echo "❌ Foundry is not installed!"
    echo ""
    echo "Install it with:"
    echo "  curl -L https://foundry.paradigm.xyz | bash"
    echo "  foundryup"
    echo ""
    exit 1
fi

echo "✅ Foundry is installed ($(forge --version | head -1))"

# Install dependencies
echo "📦 Installing forge-std..."
if [ -d "lib/forge-std" ]; then
    echo "⚠️  lib/forge-std already exists, skipping..."
else
    forge install foundry-rs/forge-std
    echo "✅ forge-std installed"
fi

# Build contracts
echo "🔨 Building contracts..."
forge build

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "  forge test -vvv          # Run tests with verbose output"
echo "  forge test --gas-report  # Run tests with gas reporting"
