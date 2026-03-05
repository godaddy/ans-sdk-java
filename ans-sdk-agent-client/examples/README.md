# ANS SDK Examples

This directory contains standalone examples demonstrating ANS (Agent Name Service) verification
integration with various protocols and SDKs.

## Examples

| Example | Description | SDK Integration |
|---------|-------------|-----------------|
| [http-api](http-api/) | Simple HTTP API using `AnsClient` | ANS SDK only |
| [mcp-client](mcp-client/) | MCP (Model Context Protocol) | Anthropic MCP SDK |
| [a2a-client](a2a-client/) | A2A (Agent-to-Agent) protocol | Official A2A SDK |

## Quick Start

```bash
cd sdks/ans-java-sdk

# Build all examples
./gradlew :ans-sdk-agent-client:examples:http-api:build
./gradlew :ans-sdk-agent-client:examples:mcp-client:build
./gradlew :ans-sdk-agent-client:examples:a2a-client:build

# Run examples (requires target servers)
./gradlew :ans-sdk-agent-client:examples:http-api:run
./gradlew :ans-sdk-agent-client:examples:mcp-client:run
./gradlew :ans-sdk-agent-client:examples:a2a-client:run

# Run with custom server URL
./gradlew :ans-sdk-agent-client:examples:http-api:run --args="https://your-agent.example.com:8443"
```

## Prerequisites

1. **ANS-registered agent** - An agent with HTTPS endpoint registered in ANS
2. **For DANE verification** - TLSA DNS records configured for the agent's hostname
3. **For Badge verification** - Agent registered in the ANS transparency log
4. **For A2A example** - No additional setup required (uses Maven Central)

## Verification Policies

All examples support different ANS verification policies:

| Policy | Description |
|--------|-------------|
| `PKI_ONLY` | Standard HTTPS with system trust store |
| `DANE_REQUIRED` | Requires DANE/TLSA verification |
| `BADGE_REQUIRED` | Requires transparency log verification |
| `DANE_AND_BADGE` | Requires both DANE and Badge |
| `FULL` | DANE + Badge (maximum security) |

## Integration Patterns

### Pattern 1: High-Level API (AnsClient)

The simplest approach using `AnsClient`:

```java
AnsClient client = AnsClient.builder()
    .connectTimeout(Duration.ofSeconds(10))
    .build();

AgentConnection conn = client.connect(
    "https://agent.example.com",
    ConnectOptions.builder()
        .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
        .build());

HttpApiClient api = conn.httpApiAt(serverUrl);
String response = api.get("/health");
```

### Pattern 2: Low-Level Integration (Certificate Capture)

For SDKs that accept custom `SSLContext`:

```java
// 1. Create SSLContext with certificate capture
SSLContext sslContext = AnsVerifiedSslContextFactory.create();

// 2. Pre-verify (DANE lookup)
CompletableFuture<PreVerificationResult> preResult = verifier.preVerify(hostname, port);

// 3. Connect using the SDK (triggers TLS handshake)
// ... SDK-specific code using sslContext ...

// 4. Post-verify captured certificate
X509Certificate[] certs = CertificateCapturingTrustManager.getCapturedCertificates(hostname);
List<VerificationResult> results = verifier.postVerify(hostname, certs[0], preResult.join());

// 5. Apply policy
VerificationResult combined = verifier.combine(results, VerificationPolicy.BADGE_REQUIRED);
if (!combined.isSuccess()) {
    throw new SecurityException("ANS verification failed: " + combined.reason());
}

// 6. Clean up
CertificateCapturingTrustManager.clearCapturedCertificates(hostname);
```

## Building from Source

These examples are Gradle subprojects. Build from the root:

```bash
cd sdks/ans-java-sdk
./gradlew :ans-sdk-agent-client:examples:http-api:build
```

## Dependencies

| Example | Additional Dependencies |
|---------|------------------------|
| http-api | None (uses SDK only) |
| mcp-client | `io.modelcontextprotocol.sdk:mcp:0.17.2` |
| a2a-client | `io.github.a2asdk:a2a-java-sdk-*:1.0.0.Alpha1` |