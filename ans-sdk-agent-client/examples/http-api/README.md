# HTTP API Example

This example demonstrates ANS verification for HTTP API connections using both the
simple `AnsClient` and the full-featured `AnsVerifiedClient` with SCITT support.

## Overview

The example includes multiple verification approaches:

1. **PKI_ONLY** - Standard HTTPS with system trust store
2. **BADGE_REQUIRED** - Transparency log verification
3. **DANE_AND_BADGE** - Full DANE + Badge verification
4. **SCITT_REQUIRED** - Cryptographic proof via HTTP headers (recommended)

## Usage

```bash
# Run with default settings (PKI, Badge, DANE examples)
./gradlew :ans-sdk-agent-client:examples:http-api:run

# Run with custom server URL
./gradlew :ans-sdk-agent-client:examples:http-api:run --args="https://your-agent.example.com:8443"

# Run SCITT example (requires keystore and agent ID)
./gradlew :ans-sdk-agent-client:examples:http-api:run \
  --args="https://your-agent.example.com:8443 /path/to/keystore.p12 keystorePassword myAgentId"
```

## Code Highlights

### Example 1: PKI_ONLY - Standard HTTPS

```java
AnsClient client = AnsClient.builder()
    .connectTimeout(Duration.ofSeconds(10))
    .readTimeout(Duration.ofSeconds(30))
    .build();

// Connect with default PKI_ONLY policy
AgentConnection conn = client.connect(serverUrl);

// Make HTTP requests
HttpApiClient api = conn.httpApiAt(serverUrl);
String response = api.get("/health");
```

### Example 2: BADGE_REQUIRED - Transparency Log

```java
AnsClient client = AnsClient.create();

ConnectOptions options = ConnectOptions.builder()
    .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
    .build();

AgentConnection conn = client.connect(serverUrl, options);
```

### Example 3: DANE_AND_BADGE - Full Verification

```java
ConnectOptions options = ConnectOptions.builder()
    .verificationPolicy(VerificationPolicy.DANE_AND_BADGE)
    .build();

AgentConnection conn = client.connect(serverUrl, options);
```

### Example 4: SCITT Verification (Recommended)

Uses `AnsVerifiedClient` for mTLS and SCITT cryptographic proof:

```java
// Create client with SCITT verification
AnsVerifiedClient client = AnsVerifiedClient.builder()
    .agentId(agentId)
    .keyStorePath(keystorePath, keystorePassword)
    .policy(VerificationPolicy.SCITT_REQUIRED)
    .connectTimeout(Duration.ofSeconds(30))
    .build();

// Connect - sends preflight to exchange SCITT artifacts
AnsConnection connection = client.connect(serverUrl);

// Check server SCITT artifacts
if (connection.hasScittArtifacts()) {
    System.out.println("Server provided SCITT artifacts");
}

// Verify server certificate against policy
VerificationResult result = connection.verifyServer();
if (!result.isSuccess()) {
    throw new SecurityException("Verification failed: " + result.reason());
}

// Clean up
connection.close();
client.close();
```

## Verification Policies

| Policy | Description | Use Case |
|--------|-------------|----------|
| `PKI_ONLY` | System trust store only | Development, testing |
| `DANE_REQUIRED` | Requires DANE/TLSA | High security with DNSSEC |
| `BADGE_REQUIRED` | Requires transparency log | Legacy production |
| `DANE_AND_BADGE` | Both DANE and Badge | Maximum legacy security |
| `SCITT_REQUIRED` | Requires SCITT artifacts | **Recommended for production** |
| `SCITT_ENHANCED` | SCITT with badge fallback | Migration from badge |

## Key Classes

| Class | Purpose |
|-------|---------|
| `AnsClient` | Simple client for PKI, DANE, Badge verification |
| `AnsVerifiedClient` | Full-featured client with SCITT support and mTLS |
| `AnsConnection` | Connection handle for SCITT verification flow |
| `VerificationPolicy` | Configures which verification methods to use |
| `VerificationResult` | Verification outcome (SUCCESS, MISMATCH, NOT_FOUND, ERROR) |

## Prerequisites

- ANS-registered agent with HTTPS endpoint
- For Badge verification: Agent in ANS transparency log
- For DANE verification: TLSA DNS records configured
- For SCITT verification: Agent with receipt and status token, client keystore
