#!/usr/bin/env bash
# Day-1 smoke test for the chain: deploys TestToken, then has a brand-new key
# with zero ETH send a legacy gasPrice=0 transfer — the same path a TSS
# wallet will take. Writes deployments/local.json.
set -euo pipefail
cd "$(dirname "$0")/.."

RPC=${RPC:-http://127.0.0.1:8545}
CHAIN_ID=7773
source infra/dev-keys.env

echo "== waiting for $RPC"
for _ in $(seq 1 60); do cast block-number --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 1; done
[ "$(cast chain-id --rpc-url "$RPC")" = "$CHAIN_ID" ] || { echo "wrong chain id"; exit 1; }

echo "== deploying TestToken"
TOKEN=$(cd contracts && forge create src/TestToken.sol:TestToken \
  --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" --legacy --gas-price 0 --broadcast --json | jq -r '(.data // .).deployedTo')
echo "TestToken at $TOKEN"
DEPLOYER=$(cast wallet address "$DEPLOYER_KEY")
jq -n --arg t "$TOKEN" --arg d "$DEPLOYER" --argjson c "$CHAIN_ID" --arg rpc "$RPC" \
  '{chainId: $c, rpc: $rpc, testToken: $t, deployer: $d}' > deployments/local.json

echo "== fresh key with zero balance"
FRESH=$(cast wallet new --json | jq -r '(.data // .)[0].private_key')
FROM=$(cast wallet address "$FRESH")
TO=$(cast wallet address "$(cast wallet new --json | jq -r '(.data // .)[0].private_key')")
echo "sender $FROM (ETH balance $(cast balance "$FROM" --rpc-url "$RPC")), recipient $TO"

cast send "$TOKEN" "mint(address,uint256)" "$FROM" 100ether \
  --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" --legacy --gas-price 0 >/dev/null

echo "== legacy transfer with gasPrice=0, chainId $CHAIN_ID (EIP-155)"
TX=$(cast send "$TOKEN" "transfer(address,uint256)" "$TO" 1ether \
  --rpc-url "$RPC" --private-key "$FRESH" --legacy --gas-price 0 --json)
STATUS=$(jq -r '(.data // .).status' <<<"$TX"); HASH=$(jq -r '(.data // .).transactionHash' <<<"$TX")
GOT=$(cast call "$TOKEN" "balanceOf(address)(uint256)" "$TO" --rpc-url "$RPC" | awk '{print $1}')
echo "tx $HASH status $STATUS, recipient balance $GOT"

[ "$STATUS" = "0x1" ] && [ "$GOT" = "1000000000000000000" ] && echo "SMOKE: PASS" || { echo "SMOKE: FAIL"; exit 1; }
