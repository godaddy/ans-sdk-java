# MCP Client Example

This example demonstrates ANS verification integration with the official
[MCP (Model Context Protocol) Java SDK](https://github.com/modelcontextprotocol/java-sdk).

## Overview

The MCP SDK's `HttpClientStreamableHttpTransport` accepts a custom `HttpClient.Builder`,
allowing us to inject an `SSLContext` configured for ANS certificate capture.

## Usage

```bash
# Run with default settings
./gradlew :ans-sdk-agent-client:examples:mcp-client:run

# Run with custom server URL
./gradlew :ans-sdk-agent-client:examples:mcp-client:run --args="https://your-mcp-server.example.com"
```

## Integration Pattern

The integration follows a **Pre-verify / Connect / Post-verify** pattern:

```java
// 1. Set up ConnectionVerifier
ConnectionVerifier verifier = DefaultConnectionVerifier.builder()
    .daneVerifier(new DaneVerifier(new DefaultDaneTlsaVerifier(DaneConfig.defaults())))
    .badgeVerifier(new BadgeVerifier(agentVerificationService))
    .build();

// 2. Pre-verify (async DANE lookup)
CompletableFuture<PreVerificationResult> preResultFuture = verifier.preVerify(hostname, port);

// 3. Create SSLContext with certificate capture
SSLContext sslContext = AnsVerifiedSslContextFactory.create();

// 4. Create MCP transport with custom SSLContext
HttpClientStreamableHttpTransport transport = HttpClientStreamableHttpTransport
    .builder(serverUrl)
    .customizeClient(builder -> builder.sslContext(sslContext))
    .build();

// 5. Create and initialize MCP client
McpSyncClient mcpClient = McpClient.sync(transport).build();
mcpClient.initialize();

// 6. Post-verify captured certificate
X509Certificate[] certs = CertificateCapturingTrustManager.getCapturedCertificates(hostname);
List<VerificationResult> results = verifier.postVerify(hostname, certs[0], preResultFuture.join());

// 7. Apply policy
VerificationResult combined = verifier.combine(results, VerificationPolicy.BADGE_REQUIRED);
if (!combined.isSuccess()) {
    mcpClient.closeGracefully();
    throw new SecurityException("ANS verification failed: " + combined.reason());
}

// 8. Use verified MCP client
var tools = mcpClient.listTools();

// 9. Clean up
CertificateCapturingTrustManager.clearCapturedCertificates(hostname);
```

## Key Classes

| Class | Purpose |
|-------|---------|
| `AnsVerifiedSslContextFactory` | Creates SSLContext with certificate capture |
| `CertificateCapturingTrustManager` | Stores certificates during TLS handshake |
| `DefaultConnectionVerifier` | Coordinates DANE, Badge verification |
| `PreVerificationResult` | Holds pre-connection expectations |
| `VerificationResult` | Holds post-connection verification results |

## Prerequisites

- MCP server with HTTPS endpoint
- For Badge verification: Agent in ANS transparency log
- For DANE verification: TLSA DNS records configured

## Dependencies

```kotlin
dependencies {
    implementation("io.modelcontextprotocol.sdk:mcp:0.17.2")
}
```