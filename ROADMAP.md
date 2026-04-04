# CertifyChain Testnet Roadmap

## Core Blockchain Infrastructure

- [ ] **Blockchain State Management**
  - `Blockchain` struct to manage chain state (blocks, transactions)
  - `addBlock()` method to append validated blocks
  - `getBlock()` / `getTransaction()` lookup methods
  - Chain reorganization support (revert invalid forks)
  - Genesis block initialization with hardcoded params

- [ ] **Transaction Pool (Mempool)**
  - `Mempool` struct to hold pending transactions
  - `add()` with duplicate/spam detection
  - `remove()` when transaction is mined
  - `getPending()` to retrieve all valid pending transactions
  - Fee estimation support
  - Transaction TTL/expiration

- [ ] **Block Validation**
  - `validate()` method to verify block structure
  - Previous block hash verification
  - Transaction validation (signature, idempotency)
  - Merkle root calculation
  - Difficulty target validation

- [ ] **Consensus Mechanism**
  - Proof of Work (PoW) with `mine()` function
  - Configurable difficulty
  - Block time targeting
  - Fork choice rule (longest valid chain)

- [ ] **Chain Synchronization**
  - `SyncProtocol` for syncing blocks between nodes
  - Headers-first sync support
  - Block request/response messages
  - Inventory-based block distribution

## Networking & P2P

- [ ] **Bootstrap Nodes**
  - Configure hardcoded bootstrap node addresses
  - Auto-connect on startup
  - Reconnection logic with backoff

- [ ] **Peer Discovery**
  - DNS-based discovery
  - Kademlia DHT integration for peer exchange
  - Peer score/penalty system
  - Connection draining on shutdown

- [ ] **P2P Message Serialization**
  - `Message` struct with proper serialization (JSON/BSON)
  - Protocol versioning
  - Message acknowledgment system
  - Compression for large payloads

- [ ] **Protocol Messages**
  - `Version` / `Verack` handshake
  - `GetHeaders` / `Headers` for sync
  - `GetBlocks` / `Block` for block propagation
  - `Inv` for inventory announcements
  - `GetData` / `NotFound` for tx/block requests

- [ ] **Network Events**
  - Event emission for new blocks, transactions, peers
  - Subscription model for external listeners
  - Connection state change notifications

## API & Interoperability

- [ ] **RPC Server**
  - HTTP server with JSON-RPC 2.0 interface
  - Standard RPC methods:
    - `getblockchaininfo`
    - `getblock`
    - `gettransaction`
    - `sendtransaction`
    - `getbalance`
    - `listtransactions`
  - Batch request support
  - CORS headers for web wallets

- [ ] **REST API** (optional)
  - `/api/v1/certificates` - certificate CRUD
  - `/api/v1/verify/:id` - verification endpoint
  - `/api/v1/blocks` - block listing
  - OpenAPI/Swagger documentation

- [ ] **WebSocket Support**
  - Real-time block/transaction notifications
  - Subscription to specific addresses
  - Reconnection handling

## Certificate Operations

- [ ] **Certificate Issuance Flow**
  - `IssueCertificate` transaction type
  - Issuer registration/verification
  - IPFS metadata storage
  - Certificate record creation

- [ ] **Certificate Revocation Flow**
  - `RevokeCertificate` transaction type
  - Revocation reason handling
  - CRL (Certificate Revocation List) support
  - Revocation broadcast

- [ ] **Certificate Verification**
  - Full chain verification (issuer → cert → revocation)
  - Signature verification against issuer public key
  - Expiry validation
  - Multi-source verification (network query)

- [ ] **Issuer Management**
  - Issuer registration
  - Issuer reputation/scoring
  - Authorized issuer list

## Storage & Persistence

- [ ] **Database Backend**
  - SQLite/BoltDB for chain state
  - Block indexing by hash and height
  - Transaction indexing by ID
  - Certificate lookup tables

- [ ] **Chain Persistence**
  - Automatic checkpointing
  - Pruned mode support (UTXO-style)
  - Database compaction
  - Recovery from corruption

- [ ] **Config File**
  - TOML/YAML configuration
  - Network-specific configs (mainnet, testnet, regtest)
  - Datadir, log level, RPC settings

## Security & Reliability

- [ ] **Transaction Validation**
  - Double-spend prevention
  - Signature verification
  - Input/utxo validation
  - Replay attack protection

- [ ] **Network Security**
  - TLS for RPC connections
  - Peer authentication
  - Eclipse attack prevention
  - Rate limiting

- [ ] **Error Handling**
  - Graceful shutdown
  - Panic recovery
  - Structured logging
  - Metrics and health checks

## Testing & Quality

- [ ] **Unit Tests**
  - >80% code coverage target
  - Fuzzing for parsers
  - Property-based tests for cryptographic operations

- [ ] **Integration Tests**
  - Multi-node network testing
  - Fork scenarios
  - Sync verification

- [ ] **Testnet Deployment**
  - 3-5 bootstrap nodes
  - Faucet for test tokens
  - Block explorer (basic)
  - Monitoring/alerting

## Documentation

- [ ] **Architecture Documentation**
  - System design overview
  - Module relationships
  - Data flow diagrams

- [ ] **API Documentation**
  - RPC method reference
  - Request/response examples
  - Error codes

- [ ] **Operator Guide**
  - Node setup instructions
  - Configuration reference
  - Troubleshooting guide

- [ ] **User Guide**
  - Certificate issuance tutorial
  - Verification walkthrough
  - SDK usage examples

## Optional Enhancements

- [ ] **Light Client (SPV)**
  - Simplified payment verification
  - Header-only sync
  - Merkle proof verification

- [ ] **Smart Contract Support** (future)
  - Basic scripting language
  - Certificate validation rules

- [ ] **Cross-Chain Bridges** (future)
  - Multi-chain certificate verification
  - Bridge contract support
