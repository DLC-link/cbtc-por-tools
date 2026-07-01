# Bitcoin Address Calculation for CBTC Bridge

This document explains how to independently calculate and verify Bitcoin deposit addresses for the CBTC bridge system, enabling trustless verification of BTC reserves.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Address Derivation Algorithm](#address-derivation-algorithm)
- [Implementation Guide](#implementation-guide)
- [API Reference](#api-reference)
- [Security Considerations](#security-considerations)

---

## Overview

The CBTC bridge uses **Taproot (P2TR) addresses** with **script-path spending**. Each deposit account has a unique address derived from:

1. A **deposit account ID** (from Canton blockchain)
2. An **aggregated threshold public key** (x-only pubkey)
3. A **deterministic unspendable key** (derived from the deposit ID)

This design enables threshold signature verification while ensuring each deposit account has a unique, deterministic address.

### Why This Matters

Traditional "Proof of Reserve" systems require trusting the bridge operator to provide accurate address lists. This implementation enables **zero-trust verification**:

- 🔐 **Trustless**: Third parties (like Chainlink) can independently calculate all addresses
- 🔍 **Verifiable**: All addresses are derived from the threshold pubkey, not provided by the operator
- 🚫 **Censorship-resistant**: Operators cannot hide or exclude addresses
- ✅ **Complete**: Every deposit account must have a corresponding address

---

## Quick Start

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/cbtc-por-tools.git
cd cbtc-por-tools
npm install
```

### Calculate Bitcoin Reserves

```bash
# Calculate reserves against the default endpoint
npm run calculate

# Or point at a different endpoint URL
npm run calculate https://your-host/cbtc/v1/address-calculation-data
```

The data URL defaults to `https://api.mainnet.bitsafe.finance/cbtc/v1/address-calculation-data`.
Override it with a CLI argument or the `ADDRESS_CALCULATION_DATA_URL` environment variable:

```bash
ADDRESS_CALCULATION_DATA_URL=https://your-host/cbtc/v1/address-calculation-data npm run calculate
```

### What It Does

The calculation script:

1. ✅ **Fetches deposit account data** from the address-calculation endpoint
2. ✅ **Independently calculates Bitcoin addresses** using the threshold pubkey and deposit IDs
3. ✅ **Verifies calculated addresses match** the reported ones
4. ✅ **Queries the Bitcoin blockchain** (via Esplora) for UTXOs at each address
5. ✅ **Sums all UTXO values** to calculate total BTC in reserve

---

## Address Derivation Algorithm

### Step 1: Get Required Data

Query the address-calculation endpoint:

```bash
GET /cbtc/v1/address-calculation-data
```

Response format:

```json
{
  "chains": [
    {
      "chain": "devnet",
      "xpub": "tpubD6NzVbkrYhZ4...",
      "addresses": [
        {
          "id": "00f8d227b43f5e0af1cd0cde4c2f49f6eacff1bf0f3eea19f42f1a40f60dc4ba4c",
          "address_for_verification": "tb1p..."
        }
      ]
    }
  ],
  "bitcoin_network": "testnet"
}
```

**Key Points:**

- The `xpub` is shared across all addresses in a chain
- Different Canton chains may use different xpubs (different signer groups)
- The xpub is **already derived to m/0/0** - no additional derivation needed

### Step 2: Parse the Extended Public Key (xpub)

The `xpub` field contains the threshold signature group's extended public key **already derived to path m/0/0**. This is a BIP32 extended public key in Base58 format.

Parse the xpub to extract:

- The public key bytes (33 bytes compressed)
- The chain code (not used for address calculation, but part of the xpub structure)

**Important:** Do NOT derive the xpub further. It is already derived to m/0/0, which is the key used for all deposit addresses on this chain.

### Step 3: Convert to X-Only Public Key

Taproot uses **x-only public keys** (32 bytes, x-coordinate only). Strip the prefix byte from the 33-byte compressed public key to get the x-only pubkey.

```javascript
const xOnlyPubkey = xpubDecoded.publicKey.slice(1); // Remove first byte
```

### Step 4: Create the Taproot Script

Build the Taproot script that will be used for script-path spending:

```
<x_only_pubkey> OP_CHECKSIG
```

This script requires a signature from the threshold group to spend funds.

### Step 5: Generate Deterministic Unspendable Key from ID

The internal key (unspendable key) is derived deterministically from the deposit account ID:

1. **Hash the ID**: SHA-256 hash the deposit account ID string to get 32 bytes
2. **Create Extended Public Key**:

   - Public Key: Fixed unspendable point `0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`
   - Chain Code: Use the hashed ID as the chain code
   - Parent Fingerprint: `00000000`
   - Depth: 3
   - Child Number: First hardened child (0x80000000)
   - Network: Match the Bitcoin network (mainnet/testnet)

3. **Derive m/0/0**: Derive the extended public key at path m/0/0 (non-hardened) using BIP32 derivation
4. **Extract X-Only Key**: Convert the derived public key to x-only format

### Step 6: Build the Taproot Output

Use the Taproot construction:

1. **Create Taproot Tree**: Build a Merkle tree with the script from Step 4
2. **Tweak the Internal Key**: Apply the Taproot tweak to the unspendable key:
   ```
   tweaked_key = internal_key + tagged_hash("TapTweak", internal_key || merkle_root) * G
   ```
3. **Create P2TR Output**: The output script is:
   ```
   OP_1 <32-byte tweaked x-only pubkey>
   ```

### Step 7: Generate the Address

Encode the P2TR output script as a Bech32m address with the appropriate network prefix:

- Mainnet: `bc1p...`
- Testnet: `tb1p...`
- Regtest: `bcrt1p...`

---

## Implementation Guide

### Constants

```javascript
const UNSPENDABLE_PUBLIC_KEY = '0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0';
const PARENT_FINGERPRINT = '00000000';
const DEPTH = 3;
```

### Recommended Libraries

- **TypeScript/JavaScript**: `bitcoinjs-lib`, `bip32`, `tiny-secp256k1`
- **Python**: `python-bitcoinlib`, `bip32`
- **Rust**: `bitcoin`, `bip32`, `secp256k1`

### Example Calculation Flow

```
Input:
  id = "00f8d227b..."
  xpub = "tpub..."
  network = "testnet"

Step 1: Parse xpub → Extract public key (33 bytes) and chain code
Step 2: Convert to x-only pubkey (32 bytes)
Step 3: Build script: <x_only_pubkey> OP_CHECKSIG
Step 4: Hash ID with SHA-256
Step 5: Create unspendable extended key with hashed ID as chain code
Step 6: Derive unspendable key at m/0/0
Step 7: Build Taproot tree with script
Step 8: Tweak internal key with Merkle root
Step 9: Create P2TR output script
Step 10: Encode as Bech32m address

Output: tb1p... (Taproot address)
```

### TypeScript Reference Implementation

See [`calculate-bitcoin-addresses.ts`](./calculate-bitcoin-addresses.ts) for a complete working implementation.

---

## API Reference

### GET /cbtc/v1/address-calculation-data

Returns all data needed to independently calculate Bitcoin addresses, grouped by Canton chain, with the threshold xpub for each chain.

Default endpoint:

```
GET https://api.mainnet.bitsafe.finance/cbtc/v1/address-calculation-data
```

**Purpose**: This endpoint provides the raw data (deposit IDs and xpubs) needed for third parties to independently calculate and verify all Bitcoin addresses. The addresses in the response should NOT be trusted - they are provided only for verification purposes.

**Response:**

```json
{
  "chains": [
    {
      "chain": "devnet",
      "xpub": "tpubD6NzVbkrYhZ4...",
      "addresses": [
        {
          "id": "00f8d227b...",
          "address_for_verification": "tb1p..."
        }
      ]
    }
  ],
  "bitcoin_network": "testnet"
}
```

**Fields:**

- `chains`: Array of chain groups (one per Canton network)
  - `chain`: Canton network name (e.g., "devnet", "mainnet")
  - `xpub`: BIP32 extended public key for this signer group (already derived to m/0/0)
  - `addresses`: Array of deposit accounts on this chain
    - `id`: Deposit account ID (hex string)
    - `address_for_verification`: Reported Bitcoin address (DO NOT TRUST - must be independently calculated and verified!)
- `bitcoin_network`: Bitcoin network ("mainnet", "testnet", "regtest")

**Important:** The script **does not trust** the `address_for_verification` field. It independently calculates each address and verifies it matches. This prevents the data source from providing incorrect addresses.

---

## Verification Process

To verify the bridge's Bitcoin holdings:

1. **Fetch all deposit data** from the address-calculation endpoint
2. **For each chain**, use the already-derived `xpub` to independently calculate addresses
3. **Verify calculated addresses match** the reported ones
4. **Query Bitcoin blockchain** (via Esplora, Electrum, or Bitcoin Core) for UTXOs at each address
5. **Sum all UTXO values** to get total BTC in the bridge

This ensures:

- ✅ Addresses are correctly derived from the threshold pubkey
- ✅ No addresses can be excluded or added
- ✅ UTXO data comes from the Bitcoin blockchain, not the data source
- ✅ Complete trustless verification of proof of reserves

## Example Output

```
================================================================================
Bitcoin Address Calculation and Proof of Reserve
================================================================================

Network: testnet
Total deposit accounts: 42

Chain: devnet (xpub: tpubD6NzVbkrYhZ4...)
✅ tb1p3xk2...: 2 UTXOs, 0.5 BTC
✅ tb1p7ym9...: 1 UTXO, 1.2 BTC
✅ tb1pqrs4...: 3 UTXOs, 0.8 BTC

================================================================================
Summary
================================================================================
✅ Verified addresses: 42/42

Total UTXOs: 156
Total BTC in Reserve: 12.34567890 BTC
================================================================================
```

---

## Dependencies

- **bitcoinjs-lib**: Bitcoin protocol implementation
- **bip32**: BIP32 extended key derivation
- **tiny-secp256k1**: Elliptic curve cryptography for Bitcoin

Install with:

```bash
npm install bitcoinjs-lib bip32 tiny-secp256k1 @types/node ts-node typescript
```

---

## License

Apache-2.0
