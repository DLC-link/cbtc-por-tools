#!/usr/bin/env ts-node

/**
 * Bitcoin Address Calculation and Proof of Reserve Calculator for CBTC Bridge
 *
 * This script independently calculates Bitcoin deposit addresses for the CBTC bridge
 * and sums all UTXOs to verify the total BTC held in reserve.
 *
 * The key principle is TRUSTLESSNESS - we never trust the reported addresses.
 * Instead, we independently calculate every address from the threshold public key
 * and deposit account IDs, then verify they match what the endpoint reports.
 *
 * Usage:
 *   npm install
 *   npm run calculate                # uses the default endpoint
 *   npm run calculate <data_url>     # or a custom endpoint URL
 *
 * The data URL defaults to DEFAULT_DATA_URL below and can be overridden with a
 * CLI argument or the ADDRESS_CALCULATION_DATA_URL environment variable.
 */

import * as bitcoin from 'bitcoinjs-lib';
import BIP32Factory from 'bip32';
import * as crypto from 'crypto';
import * as ecc from 'tiny-secp256k1';

// Initialize ECC library for bitcoinjs-lib (required for Taproot operations)
bitcoin.initEccLib(ecc);

// Initialize BIP32 library with elliptic curve implementation
const bip32 = BIP32Factory(ecc);

// Default address-calculation data endpoint. Override with a CLI argument or
// the ADDRESS_CALCULATION_DATA_URL environment variable.
const DEFAULT_DATA_URL = 'https://api.mainnet.bitsafe.finance/cbtc/v1/address-calculation-data';

/**
 * Constants from the Rust implementation
 * These must match exactly to generate the correct addresses
 */

// Fixed unspendable public key used as the base for internal key derivation
// This key is intentionally chosen to be unspendable to enhance security
const UNSPENDABLE_PUBLIC_KEY = '0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0';

// Parent fingerprint for BIP32 derivation (all zeros = root/no parent)
const PARENT_FINGERPRINT = Buffer.from('00000000', 'hex');

// Depth in the BIP32 hierarchy (3 = third level of derivation)
const DEPTH = 3;

/**
 * TypeScript interfaces matching the API response structure
 */

// Individual address info for a single deposit account
interface AddressInfo {
  id: string; // Deposit account ID (hex string)
  address_for_verification: string; // Bitcoin P2TR address (DO NOT TRUST - calculate independently!)
}

// Group of addresses sharing the same xpub (one per Canton chain)
interface ChainAddressGroup {
  chain: string; // Canton network name (e.g., "devnet")
  xpub: string; // BIP32 extended public key (already derived to m/0/0)
  addresses: AddressInfo[]; // All deposit accounts on this chain
}

// Top-level API response
interface ApiResponse {
  chains: ChainAddressGroup[]; // Array of chain groups
  bitcoin_network: string; // "mainnet", "testnet", or "regtest"
}

// UTXO data structure from Esplora API
interface UTXO {
  txid: string; // Transaction ID
  vout: number; // Output index
  value: number; // Value in satoshis
  status: {
    confirmed: boolean; // Whether transaction is confirmed
    block_height?: number; // Block height if confirmed
  };
}

/**
 * Hash a string using SHA-256
 *
 * This is used to derive the chain code for the unspendable key from the deposit ID.
 * The deterministic nature ensures the same ID always produces the same address.
 *
 * @param input - String to hash (typically the deposit account ID)
 * @returns 32-byte SHA-256 hash
 */
function hashString(input: string): Buffer {
  return crypto.createHash('sha256').update(input, 'utf8').digest();
}

/**
 * Convert network string to bitcoinjs-lib network object
 *
 * @param networkStr - Network name from API ("mainnet", "testnet", "regtest")
 * @returns Bitcoin network configuration object
 */
function getBitcoinNetwork(networkStr: string): bitcoin.Network {
  switch (networkStr.toLowerCase()) {
    case 'mainnet':
    case 'bitcoin':
      return bitcoin.networks.bitcoin;
    case 'testnet':
      return bitcoin.networks.testnet;
    case 'regtest':
      return bitcoin.networks.regtest;
    default:
      throw new Error(`Unknown network: ${networkStr}`);
  }
}

/**
 * Derive the unspendable internal key from a deposit ID
 *
 * This creates a deterministic but unspendable key that serves as the
 * Taproot internal key. The key is "unspendable" because:
 * 1. The base public key has no known private key
 * 2. It's tweaked with the Taproot script tree
 *
 * The Rust implementation creates an ExtendedPubKey with:
 * - publicKey: UNSPENDABLE_PUBLIC_KEY
 * - chainCode: SHA256(id)
 * - depth: 3
 * - parentFingerprint: 0x00000000
 * - childNumber: first hardened child (0x80000000)
 *
 * Then derives it at m/0/0 to get the final internal key.
 *
 * We simplify by directly computing the derived public key using BIP32 math,
 * which produces the same result as the Rust implementation.
 *
 * @param id - Deposit account ID (hex string from Canton)
 * @param network - Bitcoin network configuration
 * @returns X-only public key (32 bytes, for Taproot)
 */
function deriveUnspendableKey(id: string, network: bitcoin.Network): Buffer {
  // Hash the deposit ID to get a deterministic 32-byte chain code
  // This makes the internal key unique per deposit account
  const chainCode = hashString(id);

  // Parse the fixed unspendable public key (33 bytes, compressed format)
  const publicKey = Buffer.from(UNSPENDABLE_PUBLIC_KEY, 'hex');

  // Create the extended key with our custom chain code
  // The chain code derived from the ID ensures uniqueness
  const extendedKey = bip32.fromPublicKey(publicKey, chainCode, network);

  // Derive at path m/0/0 using BIP32 non-hardened derivation
  // Child 0, then another child 0
  const derived = extendedKey.derive(0).derive(0);

  // Return x-only public key by stripping the first byte (0x02 or 0x03 prefix)
  // Taproot uses 32-byte x-only keys instead of 33-byte compressed keys
  return derived.publicKey.slice(1);
}

/**
 * Calculate the Taproot address for a deposit account
 *
 * This is the core algorithm that independently calculates the Bitcoin address.
 * The address is a P2TR (Pay-to-Taproot) address with script-path spending enabled.
 *
 * Steps:
 * 1. Create Taproot script: <x_only_pubkey> OP_CHECKSIG
 * 2. Derive unspendable internal key from deposit ID
 * 3. Build Taproot tree with the script
 * 4. Tweak internal key with tree hash (BIP341)
 * 5. Create P2TR output script
 * 6. Encode as Bech32m address
 *
 * @param id - Deposit account ID (hex string)
 * @param xOnlyPubkey - X-only threshold group public key (32 bytes)
 * @param network - Bitcoin network configuration
 * @returns Taproot address (Bech32m encoded)
 */
function calculateTaprootAddress(id: string, xOnlyPubkey: Buffer, network: bitcoin.Network): string {
  // Step 1: Create the Taproot script for script-path spending
  // This script requires a Schnorr signature from the threshold group pubkey
  // Format: <32-byte x-only pubkey> OP_CHECKSIG
  const script = bitcoin.script.compile([xOnlyPubkey, bitcoin.opcodes.OP_CHECKSIG]);

  // Step 2: Get the unspendable internal key (deterministic from deposit ID)
  // This key is used as the Taproot internal key and will be tweaked
  const internalPubkey = deriveUnspendableKey(id, network);

  // Step 3: Calculate the taproot tree hash (TapLeaf hash)
  // The leaf version 0xc0 indicates TAPROOT_LEAF_TAPSCRIPT
  const leafVersion = 0xc0;

  // Build the leaf: version || compact_size(script_length) || script
  const tapLeaf = Buffer.concat([Buffer.from([leafVersion]), bitcoin.script.compile([script.length]), script]);

  // Calculate tagged hash: SHA256(SHA256("TapLeaf") || SHA256("TapLeaf") || leaf_data)
  // Tagged hashes are used throughout Taproot to prevent cross-protocol attacks
  const tagHash = crypto.createHash('sha256').update('TapLeaf').digest();
  const taggedHash = crypto
    .createHash('sha256')
    .update(Buffer.concat([tagHash, tagHash, tapLeaf]))
    .digest();

  // Step 4: Calculate the Taproot tweak
  // tweak = tagged_hash("TapTweak", internal_pubkey || merkle_root)
  // The tweak commits to both the internal key and the script tree
  const tapTweakTag = crypto.createHash('sha256').update('TapTweak').digest();
  const tapTweakHash = crypto
    .createHash('sha256')
    .update(Buffer.concat([tapTweakTag, tapTweakTag, internalPubkey, taggedHash]))
    .digest();

  // Step 5: Tweak the internal key by adding the tweak point
  // This produces the final Taproot output key: Q = P + hash(P || m)G
  // where P is internal key, m is merkle root, G is generator point
  const tweakedKey = ecc.xOnlyPointAddTweak(internalPubkey, tapTweakHash);
  if (!tweakedKey) {
    throw new Error('Failed to tweak public key - this should never happen');
  }

  // Step 6: Create the P2TR payment and encode as Bech32m address
  // bitcoinjs-lib handles the address encoding for us
  const payment = bitcoin.payments.p2tr({
    internalPubkey, // Original internal key (not tweaked)
    scriptTree: {
      output: script, // The script we want to commit to
    },
    network,
  });

  if (!payment.address) {
    throw new Error('Failed to generate address - invalid payment');
  }

  return payment.address;
}

/**
 * Fetch the address-calculation data (chains, xpubs, deposit IDs, network).
 *
 * @param dataUrl - Full URL of the address-calculation data endpoint
 * @returns API response with chains and addresses
 */
async function fetchDepositAddresses(dataUrl: string): Promise<ApiResponse> {
  console.log(`Fetching address calculation data from: ${dataUrl}`);

  const response = await fetch(dataUrl);
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }

  return (await response.json()) as ApiResponse;
}

/**
 * Get the Esplora URL for the given network
 *
 * @param network - Bitcoin network configuration
 * @returns Esplora API base URL
 */
function getEsploraUrl(network: bitcoin.Network): string {
  // If ESPLORA_API env var is set, always use it regardless of network
  if (process.env.ESPLORA_API) {
    return process.env.ESPLORA_API;
  }

  // Otherwise fall back to default public Esplora instances
  // Note: public Esplora endpoints are rate limited
  if (network === bitcoin.networks.bitcoin) {
    return 'https://blockstream.info/api';
  } else if (network === bitcoin.networks.testnet) {
    return 'https://blockstream.info/testnet/api';
  } else {
    // Regtest uses local Esplora instance (electrs)
    return 'http://localhost:3004';
  }
}

/**
 * Sleep for the given number of milliseconds.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Fetch a URL and parse the body as JSON, retrying on transient failures.
 *
 * Public Esplora endpoints are rate limited and occasionally return transient
 * 5xx errors or drop the connection. A single failure must NEVER be silently
 * treated as "no data" — for a proof-of-reserve tool, silently mapping a failed
 * UTXO lookup to "zero balance" would understate the reserve. So we retry with
 * exponential backoff and, if every attempt fails, throw so the caller can
 * record the failure explicitly instead of counting the address as empty.
 *
 * Only transient failures are retried: network-level errors and the HTTP
 * statuses worth retrying (`429 Too Many Requests` and `5xx`). Other 4xx
 * responses (e.g. 400/404) are client errors that will not succeed on retry, so
 * they fail immediately rather than waiting through the backoff (which would
 * also worsen rate limiting).
 *
 * @param url - URL to fetch
 * @param attempts - Maximum number of attempts (default 4)
 * @returns Parsed JSON body
 * @throws Immediately on a non-transient (non-429 4xx) response, or after all
 *   attempts are exhausted on transient failures.
 */
async function fetchJsonWithRetry(url: string, attempts = 4): Promise<unknown> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    let response: Response;
    try {
      response = await fetch(url);
    } catch (error) {
      // Network-level failure (DNS, connection reset, TLS) — transient, retry.
      lastError = error;
      if (attempt < attempts) {
        await sleep(500 * 2 ** (attempt - 1)); // Exponential backoff: 500ms, 1s, 2s, ...
      }
      continue;
    }

    if (response.ok) {
      return await response.json();
    }

    // Non-2xx response. Retry only transient statuses (429 or 5xx); other 4xx
    // are client errors that will not succeed on retry, so fail immediately.
    lastError = new Error(`HTTP ${response.status} ${response.statusText} for ${url}`);
    const transient = response.status === 429 || response.status >= 500;
    if (!transient) {
      throw lastError;
    }
    if (attempt < attempts) {
      await sleep(500 * 2 ** (attempt - 1)); // Exponential backoff: 500ms, 1s, 2s, ...
    }
  }
  const reason = lastError instanceof Error ? lastError.message : String(lastError);
  throw new Error(`failed to fetch ${url} after ${attempts} attempts (${reason})`);
}

/**
 * Fetch current block height from Esplora API
 *
 * Block height is non-fatal: without it we cannot compute confirmations, so the
 * caller falls back to counting all confirmed UTXOs. We still retry transient
 * failures before giving up.
 *
 * @param network - Bitcoin network configuration
 * @returns Current block height, or undefined if it cannot be fetched
 */
async function fetchBlockHeight(network: bitcoin.Network): Promise<number | undefined> {
  const esploraUrl = getEsploraUrl(network);
  const url = `${esploraUrl}/blocks/tip/height`;

  try {
    return (await fetchJsonWithRetry(url)) as number;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    console.warn(`Warning: could not fetch block height (${reason}).`);
    return undefined;
  }
}

/**
 * Fetch UTXOs for an address using the Esplora API
 *
 * This queries the Bitcoin blockchain to find all unspent outputs (UTXOs)
 * at a given address. We use public Esplora instances for simplicity.
 *
 * For production use, consider running your own Esplora instance or using
 * multiple sources (Electrum, Bitcoin Core RPC) for redundancy.
 *
 * @param address - Bitcoin address (P2TR/Bech32m format)
 * @param network - Bitcoin network configuration
 * @returns Array of UTXOs at this address
 * @throws If UTXOs cannot be fetched after retries. Callers MUST treat this as
 *   "reserve unknown for this address", never as "zero balance" — otherwise the
 *   reported reserve would be silently understated.
 */
async function fetchUTXOs(address: string, network: bitcoin.Network): Promise<UTXO[]> {
  const esploraUrl = getEsploraUrl(network);
  const url = `${esploraUrl}/address/${address}/utxo`;
  return (await fetchJsonWithRetry(url)) as UTXO[];
}

/**
 * Main verification and calculation function
 *
 * This is the entry point that:
 * 1. Fetches deposit account data
 * 2. Independently calculates each Bitcoin address
 * 3. Verifies calculated addresses match the reported ones
 * 4. Queries the Bitcoin blockchain for UTXOs
 * 5. Sums all UTXO values to get total BTC in reserve
 *
 * The key security property is that we NEVER trust the reported addresses.
 * We always recalculate them from the threshold pubkey and deposit IDs.
 *
 * @param dataUrl - Full URL of the address-calculation data endpoint
 */
async function verifyAndCalculateReserve(dataUrl: string = DEFAULT_DATA_URL): Promise<void> {
  console.log('='.repeat(80));
  console.log('Bitcoin Address Calculation and Proof of Reserve');
  console.log('='.repeat(80));
  console.log();

  // Step 1: Fetch all deposit account data
  const data = await fetchDepositAddresses(dataUrl);
  const network = getBitcoinNetwork(data.bitcoin_network);

  console.log(`Network: ${data.bitcoin_network}`);
  console.log(`Total chains: ${data.chains.length}`);
  console.log();

  // Fetch current block height to calculate confirmations
  const currentBlockHeight = await fetchBlockHeight(network);
  if (currentBlockHeight !== undefined) {
    console.log(`Current block height: ${currentBlockHeight}`);
    console.log(`Minimum confirmations required: 6`);
  } else {
    console.warn(`Warning: Could not fetch block height. All confirmed UTXOs will be counted.`);
  }
  console.log();

  // Counters for summary
  let verifiedCount = 0;
  let failedCount = 0;
  const failedAddresses: string[] = [];

  let totalBTC = 0;
  let totalUTXOs = 0;
  let totalUnconfirmedUTXOs = 0;
  let totalUnconfirmedBTC = 0;

  // Step 2: Process each chain (different Canton networks with different signer groups)
  for (const chainGroup of data.chains) {
    console.log(`Chain: ${chainGroup.chain} (xpub: ${chainGroup.xpub.substring(0, 20)}...)`);

    // Parse the xpub to get the threshold group's x-only public key
    // The xpub is already derived to m/0/0, so we just extract the pubkey
    const xpubDecoded = bip32.fromBase58(chainGroup.xpub, network);

    // Convert from 33-byte compressed key to 32-byte x-only key
    // Taproot uses x-only keys (just the x-coordinate, no prefix byte)
    const xOnlyPubkey = xpubDecoded.publicKey.slice(1);

    // Step 3: Process each deposit account on this chain
    for (const addressInfo of chainGroup.addresses) {
      try {
        // **CRITICAL STEP**: Calculate the address independently
        // We NEVER trust the reported address
        const calculatedAddress = calculateTaprootAddress(addressInfo.id, xOnlyPubkey, network);

        // Verify our calculated address matches the reported one
        // If it doesn't match, the data source is either broken or malicious
        if (calculatedAddress !== addressInfo.address_for_verification) {
          console.error(`❌ Address mismatch for ID ${addressInfo.id.substring(0, 16)}...`);
          console.error(`   Reported:   ${addressInfo.address_for_verification}`);
          console.error(`   Calculated: ${calculatedAddress}`);
          failedCount++;
          failedAddresses.push(addressInfo.id);
          continue;
        }

        verifiedCount++;

        // Step 4: Fetch UTXOs from the Bitcoin blockchain
        // This is the actual proof of reserve - checking what BTC exists on-chain.
        // fetchUTXOs already retries transient failures with backoff. If it still
        // fails, we cannot read this address's balance — so we abort the entire
        // run rather than skip it or count it as zero. A proof-of-reserve total is
        // only meaningful if it covers every address; a partial total would be
        // misleading, so we report none.
        let utxos: UTXO[];
        try {
          utxos = await fetchUTXOs(calculatedAddress, network);
        } catch (error) {
          const reason = error instanceof Error ? error.message : String(error);
          console.error();
          console.error(`❌ Could not read on-chain UTXOs for ${calculatedAddress} after retries (${reason}).`);
          console.error(`   Aborting without a reserve total — a complete on-chain read is required for a`);
          console.error(`   trustworthy result. Check your Esplora endpoint (ESPLORA_API) and re-run.`);
          process.exit(1);
        }

        // Filter UTXOs to only count those with 6+ confirmations
        const confirmedUtxos = utxos.filter((utxo) => {
          if (!utxo.status.confirmed) {
            return false; // Unconfirmed transaction
          }
          if (currentBlockHeight === undefined || utxo.status.block_height === undefined) {
            // If we can't determine confirmations, count all confirmed UTXOs
            return true;
          }
          const confirmations = currentBlockHeight - utxo.status.block_height + 1;
          return confirmations >= 6;
        });

        const unconfirmedUtxos = utxos.filter((utxo) => {
          if (!utxo.status.confirmed) {
            return true; // Unconfirmed transaction
          }
          if (currentBlockHeight === undefined || utxo.status.block_height === undefined) {
            return false;
          }
          const confirmations = currentBlockHeight - utxo.status.block_height + 1;
          return confirmations < 6;
        });

        const addressValue = confirmedUtxos.reduce((sum, utxo) => sum + utxo.value, 0);
        const unconfirmedValue = unconfirmedUtxos.reduce((sum, utxo) => sum + utxo.value, 0);

        totalUTXOs += confirmedUtxos.length;
        totalBTC += addressValue;
        totalUnconfirmedUTXOs += unconfirmedUtxos.length;
        totalUnconfirmedBTC += unconfirmedValue;

        // Only print addresses that have UTXOs (to reduce noise)
        if (confirmedUtxos.length > 0 || unconfirmedUtxos.length > 0) {
          const parts = [];
          if (confirmedUtxos.length > 0) {
            parts.push(`${confirmedUtxos.length} UTXOs (6+ conf), ${addressValue / 1e8} BTC`);
          }
          if (unconfirmedUtxos.length > 0) {
            parts.push(`${unconfirmedUtxos.length} UTXOs (<6 conf), ${unconfirmedValue / 1e8} BTC`);
          }
          console.log(`✅ ${calculatedAddress}: ${parts.join(' | ')}`);
        }
      } catch (error) {
        console.error(`❌ Error processing ${addressInfo.id.substring(0, 16)}...:`, error);
        failedCount++;
        failedAddresses.push(addressInfo.id);
      }
    }

    console.log(); // Blank line between chains
  }

  // Step 5: Print summary
  console.log('='.repeat(80));
  console.log('Summary');
  console.log('='.repeat(80));
  console.log(`✅ Verified addresses: ${verifiedCount}/${verifiedCount + failedCount}`);
  if (failedCount > 0) {
    console.log(`❌ Failed addresses: ${failedCount}`);
    console.log(`   Failed IDs: ${failedAddresses.map((id) => id.substring(0, 16)).join(', ')}...`);
  }
  console.log();
  console.log(`Confirmed UTXOs (6+ confirmations): ${totalUTXOs}`);
  console.log(`Total BTC in Reserve (6+ conf): ${(totalBTC / 1e8).toFixed(8)} BTC`);
  if (totalUnconfirmedUTXOs > 0) {
    console.log();
    console.log(`Unconfirmed UTXOs (<6 confirmations): ${totalUnconfirmedUTXOs}`);
    console.log(`Total BTC pending (<6 conf): ${(totalUnconfirmedBTC / 1e8).toFixed(8)} BTC`);
  }
  console.log('='.repeat(80));

  // Exit with an error code if any address failed verification. (A UTXO lookup
  // that fails after retries aborts the run earlier, before this summary, so an
  // incomplete reserve total is never printed.)
  if (failedCount > 0) {
    process.exit(1);
  }
}

// Main execution
if (require.main === module) {
  // Resolve the data URL: CLI argument, then env var, then the default.
  const dataUrl = process.argv[2] || process.env.ADDRESS_CALCULATION_DATA_URL || DEFAULT_DATA_URL;

  verifyAndCalculateReserve(dataUrl)
    .then(() => {
      console.log('✅ Verification complete!');
      process.exit(0);
    })
    .catch((error) => {
      console.error('❌ Verification failed:', error);
      process.exit(1);
    });
}

// Export functions for use as a library
export { calculateTaprootAddress, verifyAndCalculateReserve };
