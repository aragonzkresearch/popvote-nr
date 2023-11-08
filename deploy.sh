#!/bin/bash
set -e

RPC_URL="http://localhost:8545"
export REGISTRY_ADDRESS="0x5fbdb2315678afecb367f032d93f642f64180aa3"

# DEPLOY ETHEREUM CONTRACT
echo "Deploying Ethereum contracts..."
cd ethereum_contract/
ETHEREUM_DEPLOYMENT=$(forge script script/POPVoteNr.s.sol:POPVoteNrScript --fork-url "$RPC_URL" --broadcast --verify)
export PORTAL_ADDRESS=$(echo "$ETHEREUM_DEPLOYMENT" | grep "POPVoteNr contract address" | awk '{print $NF}')
NFT_CONTRACT_ADDRESS=$(echo "$ETHEREUM_DEPLOYMENT" | grep "NFT contract address" | awk '{print $NF}')
ZK_REGISTRY_ADDRESS=$(echo "$ETHEREUM_DEPLOYMENT" | grep "ZKRegistry contract address" | awk '{print $NF}')
# DEPLOY AZTEC CONTRACT
echo "Compiling Aztec contract..."
cd ../contract/
#aztec-cli compile --interface ./src ./
echo "Deploying Aztec contract..."
AZTEC_DEPLOYMENT=$(aztec-cli deploy ./target/POPVote.json -p "$PORTAL_ADDRESS" -a "$NFT_CONTRACT_ADDRESS" "$ZK_REGISTRY_ADDRESS")
export L2_CONTRACT_ADDRESS=$(echo "$AZTEC_DEPLOYMENT" | grep "Contract deployed at" | awk '{print $NF}')
echo $L2_CONTRACT_ADDRESS
# Initialise ETHEREUM CONTRACT
echo "Initialising Ethereum contract..."
cd ../ethereum_contract/
forge script script/POPVoteNr.s.sol:POPVoteNrInitScript --fork-url "$RPC_URL" --broadcast --verify
