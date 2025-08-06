# VRS-TSS: Threshold Signature Scheme MCP Server

[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Model Context Protocol (MCP) server that provides threshold signature scheme (TSS) functionality for the Verisense Network. This server acts as a bridge between TSS cryptographic operations and external applications, enabling secure multi-party signature generation through a standardized HTTP interface.

## Features

- 🔐 **Distributed Key Generation (DKG)**: Automatic distributed key generation with configurable timeout
- ✍️ **Threshold Signing**: Multi-party signature generation with key tweaking support
- 🔑 **Multiple Crypto Types**: Support for P256, Ed25519, Secp256k1, Ed448, Ristretto255, and more
- 🤖 **MCP Protocol**: Standard Model Context Protocol for AI tool integration
- 🌐 **P2P Networking**: LibP2P-based networking for distributed operations
- ⚡ **Async Runtime**: Built on Tokio for high-performance async operations

## Supported Cryptographic Types

- P256
- Ed25519
- Secp256k1 (with compressed keys and RSV signatures)
- Secp256k1Tr (with key tweaking)
- Ed448
- Ristretto255
- EcdsaSecp256k1

## Installation

### Prerequisites

- Rust 1.70+ (2024 edition)
- Cargo

### Build from Source

```bash
# Clone the repository
git clone https://github.com/verisense-network/tss-mcp.git
cd tss-mcp

# Build the project
cargo build --release

# Run tests
cargo test
```

## Configuration

Create a `.env` file in the project root with the following variables:

```env
IP=34.71.144.40
PEER_ID=12D3KooWKBJ9JWfM4fCphUhFfN9Lfcm3XBSdFBUNqCdBhfQY3enF
```

The server will use these values to connect to TSS bootstrap nodes for distributed operations.

## Usage

### Starting the MCP Server

```bash
# Run the server (default port: 8000)
cargo run

# Or run the built binary
./target/release/vrs-tss
```

The server will start on `http://0.0.0.0:80` with the MCP endpoint at `/mcp`.

### MCP Tools

The server exposes two main tools through the MCP protocol:

#### 1. Get Public Key

Retrieves a TSS public key with automatic DKG if needed.

**Parameters:**
- `crypto_type`: Cryptographic algorithm (e.g., "EcdsaSecp256k1")
- `tweak_data` (optional): Hex-encoded data for key tweaking
- `dkg_timeout` (optional): DKG timeout in seconds (default: 120)

**Example Request:**
```json
{
  "tool": "get_public_key",
  "arguments": {
    "crypto_type": "EcdsaSecp256k1",
    "tweak_data": "0x1234567890abcdef"
  }
}
```

#### 2. Sign

Performs threshold signing on a message.

**Parameters:**
- `crypto_type`: Cryptographic algorithm
- `message`: Hex-encoded message to sign
- `tweak_data` (optional): Hex-encoded data for key tweaking

**Example Request:**
```json
{
  "tool": "sign",
  "arguments": {
    "crypto_type": "EcdsaSecp256k1",
    "message": "0xdeadbeef",
    "tweak_data": "0x1234567890abcdef"
  }
}
```

### Using with MCP Clients

The server is compatible with any MCP client. Example integration:

```python
import requests

# Get public key
response = requests.post("http://127.0.0.1:80/mcp", json={
    "tool": "get_public_key",
    "arguments": {
        "crypto_type": "EcdsaSecp256k1"
    }
})

# Sign message
response = requests.post("http://127.0.0.1:80/mcp", json={
    "tool": "sign",
    "arguments": {
        "crypto_type": "EcdsaSecp256k1",
        "message": "0xdeadbeef"
    }
})
```

## Development

### Project Structure

```
tss-mcp/
├── src/
│   ├── main.rs         # MCP server implementation
│   ├── identity.rs     # Cryptographic identity management
│   ├── testing.rs      # Testing utilities
│   └── eth_pk_gen.py   # Ethereum key utilities
├── Cargo.toml          # Project dependencies
├── .env.example        # Environment configuration template
└── CLAUDE.md          # Development guidance
```

### Building and Testing

```bash
# Type check without building
cargo check

# Run linter
cargo clippy

# Format code
cargo fmt

# Run all tests
cargo test

# Run specific test
cargo test test_name

# Build optimized release
cargo build --release
```

### Key Dependencies

- **tss-sdk**: Core TSS functionality from veritss repository
- **sp-core, sp-keystore**: Substrate cryptographic primitives
- **rmcp**: Model Context Protocol framework
- **axum**: High-performance web framework
- **tokio**: Async runtime
- **libp2p-identity**: P2P networking identity

## Architecture

The TSS-MCP server implements a three-layer architecture:

1. **MCP Layer**: HTTP server exposing MCP protocol endpoints
2. **Identity Layer**: Cryptographic identity and keystore management
3. **TSS Layer**: Core threshold signature operations via tss-sdk

### Network Architecture

- Connects to bootstrap nodes via LibP2P
- Performs distributed operations with other TSS nodes
- Supports configurable network parameters via environment variables

## Use Cases

- **Multi-Party Wallets**: Secure cryptocurrency wallets requiring multiple signers
- **Distributed Validators**: Blockchain validators with distributed key management
- **Enterprise Security**: Multi-signature authorization for critical operations
- **AI Integration**: Secure signature generation for AI applications via MCP

## Security Considerations

- Never expose the MCP server directly to the internet
- Use proper authentication and authorization in production
- Secure environment variables and configuration files
- Regular security audits of cryptographic operations
- Monitor network connections to TSS nodes

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Verisense Network team for the TSS implementation
- Substrate team for cryptographic primitives
- MCP community for the protocol specification

## Support

For issues and questions:
- Open an issue on GitHub
- Contact the Verisense Network team

---

Built with ❤️ by Verisense Network