# MCP Client Example

This example demonstrates ANS verification integration with the official
[MCP (Model Context Protocol) Java SDK](https://github.com/modelcontextprotocol/java-sdk).

## Overview

The `AnsVerifiedClient` provides a high-level API that handles:
- DANE/TLSA DNS lookup and verification
- Badge (transparency log) verification
- SCITT artifact fetching and verification via HTTP headers
- mTLS client authentication with certificate capture

## Usage

```bash
# Set environment variables
export AGENT_ID=your-agent-uuid
export KEYSTORE_PATH=/path/to/client.p12
export KEYSTORE_PASS=changeit

# Run with default settings
./gradlew :ans-sdk-agent-client:examples:mcp-client:run

# Run with custom server URL
./gradlew :ans-sdk-agent-client:examples:mcp-client:run --args="https://your-mcp-server.example.com/mcp"
```

## Integration Pattern

The integration uses the high-level `AnsVerifiedClient`:

```java
// 1. Create ANS verified client with policy
try (AnsVerifiedClient ansClient = AnsVerifiedClient.builder()
        .agentId(agentId)                        // For SCITT headers (server verifies these)
        .keyStorePath(keystorePath, password)    // For mTLS client auth
        .policy(VerificationPolicy.SCITT_REQUIRED)
        .build()) {

    // 2. Connect and run pre-verifications (DANE, Badge, SCITT based on policy)
    try (AnsConnection connection = ansClient.connect(serverUrl)) {
        System.out.println("DANE records: " + connection.hasDaneRecords());
        System.out.println("Badge registration: " + connection.hasBadgeRegistration());
        System.out.println("SCITT artifacts: " + connection.hasScittArtifacts());

        // 3. Create MCP transport with ANS SSLContext and SCITT headers
        HttpClientStreamableHttpTransport transport = HttpClientStreamableHttpTransport.builder(serverUrl)
            .customizeClient(b -> b.sslContext(ansClient.sslContext()))
            .customizeRequest(b -> ansClient.scittHeaders().forEach(b::header))
            .build();

        // 4. Initialize MCP client
        McpSyncClient mcpClient = McpClient.sync(transport).build();
        mcpClient.initialize();

        // 5. Post-verify server certificate (combines all results per policy)
        VerificationResult result = connection.verifyServer();
        if (!result.isSuccess()) {
            mcpClient.closeGracefully();
            throw new SecurityException("Server verification failed: " + result.reason());
        }

        // 6. Use verified MCP client
        var tools = mcpClient.listTools();
        tools.tools().forEach(t -> System.out.println("  - " + t.name()));

        mcpClient.closeGracefully();
    }
}
```

## Verification Policies

| Policy | DANE | Badge | SCITT | Use Case |
|--------|------|-------|-------|----------|
| `PKI_ONLY` | - | - | - | Standard TLS only |
| `BADGE_REQUIRED` | - | ✓ | - | Transparency log verification |
| `DANE_REQUIRED` | ✓ | - | - | DNSSEC/TLSA verification |
| `SCITT_REQUIRED` | - | - | ✓ | **Recommended** - SCITT via HTTP headers |
| `SCITT_ENHANCED` | - | advisory | ✓ | SCITT with badge fallback |

### Fail-Fast Behavior

SCITT verification policies enforce fail-fast behavior during `connect()`:

| Policy | No Headers | Headers Present + Invalid |
|--------|------------|---------------------------|
| `SCITT_REQUIRED` | **Throws** `ScittVerificationException` | **Throws** `ScittVerificationException` |
| `SCITT_ENHANCED` | Falls back to badge verification | **Throws** `ScittVerificationException` |
| Custom ADVISORY | Falls back to badge verification | **Throws** `ScittVerificationException` |

This prevents attackers from sending garbage SCITT headers to force badge fallback.

## Key Classes

| Class | Purpose |
|-------|---------|
| `AnsVerifiedClient` | High-level client - creates SSLContext, fetches SCITT headers, coordinates verifiers |
| `AnsConnection` | Connection handle - holds pre-verification results, performs post-verification |
| `VerificationPolicy` | Configures which verification methods to use |
| `VerificationResult` | Combined verification outcome (SUCCESS, MISMATCH, NOT_FOUND, ERROR) |
| `TransparencyClient` | Fetches SCITT artifacts and root public key from Transparency Log |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AGENT_ID` | For SCITT | Client's agent UUID for SCITT header generation |
| `KEYSTORE_PATH` | For mTLS | Path to PKCS12 keystore containing client cert + key |
| `KEYSTORE_PASS` | For mTLS | Keystore password (default: changeit) |

## Creating a Client Keystore

```bash
# From PEM files:
openssl pkcs12 -export -in cert.pem -inkey key.pem \
  -out client.p12 -name client -password pass:changeit

# Include CA chain if needed:
openssl pkcs12 -export -in cert.pem -inkey key.pem -certfile ca.pem \
  -out client.p12 -name client -password pass:changeit
```

## Prerequisites

- MCP server with HTTPS endpoint supporting mTLS
- For SCITT: Agent registered in ANS transparency log
- For Badge: Agent with valid badge in transparency log
- For DANE: TLSA DNS records configured with DNSSEC

## Dependencies

```kotlin
dependencies {
    implementation("io.modelcontextprotocol.sdk:mcp:0.17.2")
    implementation(project(":ans-sdk-agent-client"))
}
```

## How It Works

1. **Build phase**: `AnsVerifiedClient.builder()` creates an SSLContext with certificate capture, fetches client's SCITT artifacts for outgoing headers, and configures verifiers based on policy.

2. **Connect phase**: `ansClient.connect(url)` sends a preflight HEAD request (if SCITT enabled) to capture server's SCITT headers, runs DANE DNS lookups, and queries badge status.

3. **MCP handshake**: The MCP SDK uses the configured SSLContext for TLS, which captures the server certificate. SCITT headers are added to all requests.

4. **Post-verify phase**: `connection.verifyServer()` checks the captured server certificate against DANE expectations, badge fingerprints, and/or SCITT status token based on policy.