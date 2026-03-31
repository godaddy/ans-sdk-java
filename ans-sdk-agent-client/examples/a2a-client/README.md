# A2A Client Example

This example demonstrates ANS verification integration with the official
[A2A (Agent-to-Agent) Java SDK](https://github.com/a2aprotocol/a2a-java).

## Overview

The example includes two verification approaches:

1. **Manual Verification** - Low-level DANE/Badge flow with certificate capture
2. **SCITT with AnsVerifiedClient** - High-level SCITT verification (recommended)

## Prerequisites

- A2A server with HTTPS endpoint (implements `/.well-known/agent-card.json`)
- For Badge verification: Agent in ANS transparency log
- For DANE verification: TLSA DNS records configured
- For SCITT verification: Agent with receipt and status token, client keystore

## Usage

```bash
# Run with default settings (Manual DANE/Badge example)
./gradlew :ans-sdk-agent-client:examples:a2a-client:run

# Run with custom server URL
./gradlew :ans-sdk-agent-client:examples:a2a-client:run --args="https://your-a2a-server.example.com:8443"

# Run SCITT example (requires keystore and agent ID)
./gradlew :ans-sdk-agent-client:examples:a2a-client:run \
  --args="https://your-server:8443 /path/to/client.p12 password agentId"
```

## Example 1: Manual DANE/Badge Verification

The manual integration follows a **Pre-verify / Connect / Post-verify** pattern:

```java
// 1. Set up ConnectionVerifier with DANE and Badge
ConnectionVerifier verifier = DefaultConnectionVerifier.builder()
    .daneVerifier(new DaneVerifier(new DefaultDaneTlsaVerifier(
        DaneConfig.builder().validationMode(DnssecValidationMode.VALIDATE_IN_CODE).build())))
    .badgeVerifier(new BadgeVerifier(
        BadgeVerificationService.builder()
            .transparencyClient(TransparencyClient.createOte())
            .build()))
    .build();

// 2. Pre-verify (async DANE lookup)
CompletableFuture<PreVerificationResult> preResultFuture = verifier.preVerify(hostname, port);

// 3. Create SSLContext with certificate capture
SSLContext sslContext = AnsVerifiedSslContextFactory.create();

// 4. Create A2A HTTP client adapter with custom SSLContext
HttpClientA2AAdapter httpClient = new HttpClientA2AAdapter(sslContext);

// 5. Fetch AgentCard (triggers TLS handshake, captures certificate)
A2ACardResolver cardResolver = new A2ACardResolver(httpClient, serverUrl, null);
AgentCard agentCard = cardResolver.getAgentCard();

// 6. Post-verify captured certificate
X509Certificate[] certs = CertificateCapturingTrustManager.getCapturedCertificates(hostname);
List<VerificationResult> results = verifier.postVerify(hostname, certs[0], preResultFuture.join());

// 7. Apply policy
VerificationResult combined = verifier.combine(results, VerificationPolicy.DANE_REQUIRED);
if (!combined.isSuccess()) {
    throw new SecurityException("ANS verification failed: " + combined.reason());
}

// 8. Create A2A client and send messages
JSONRPCTransportConfig transportConfig = new JSONRPCTransportConfig(httpClient);
Client client = Client.builder(agentCard)
    .withTransport(JSONRPCTransport.class, transportConfig)
    .build();

Message message = A2A.toUserMessage("Hello from ANS-verified client!");
client.sendMessage(message);

// 9. Clean up
CertificateCapturingTrustManager.clearCapturedCertificates(hostname);
```

## Example 2: SCITT with AnsVerifiedClient (Recommended)

The high-level approach using `AnsVerifiedClient` handles SCITT automatically:

```java
// 1. Create AnsVerifiedClient with SCITT policy
try (AnsVerifiedClient ansClient = AnsVerifiedClient.builder()
        .agentId(agentId)
        .transparencyClient(TransparencyClient.builder()
            .baseUrl(TransparencyClient.OTE_BASE_URL).build())
        .keyStorePath(keystorePath, keystorePassword)
        .policy(VerificationPolicy.SCITT_REQUIRED)
        .build()) {

    // 2. Connect (performs preflight for SCITT header exchange)
    try (AnsConnection connection = ansClient.connect(serverUrl)) {
        System.out.println("SCITT artifacts from server: " + connection.hasScittArtifacts());

        // 3. Create A2A HTTP client with ANS SSLContext
        HttpClientA2AAdapter httpClient = new HttpClientA2AAdapter(ansClient.sslContext());

        // 4. Fetch AgentCard (triggers TLS handshake)
        A2ACardResolver cardResolver = new A2ACardResolver(httpClient, serverUrl, null);
        AgentCard agentCard = cardResolver.getAgentCard();

        // 5. Post-verify server certificate
        VerificationResult result = connection.verifyServer();
        if (!result.isSuccess()) {
            throw new SecurityException("SCITT verification failed: " + result.reason());
        }

        // 6. Create A2A client and send messages
        JSONRPCTransportConfig transportConfig = new JSONRPCTransportConfig(httpClient);
        Client client = Client.builder(agentCard)
            .withTransport(JSONRPCTransport.class, transportConfig)
            .build();

        Message message = A2A.toUserMessage("Hello from SCITT-verified A2A client!");
        client.sendMessage(message);
    }
}
```

## HttpClientA2AAdapter

The adapter wraps Java's `HttpClient` to implement A2A's `A2AHttpClient` interface:

```java
public class HttpClientA2AAdapter implements A2AHttpClient {
    public HttpClientA2AAdapter(SSLContext sslContext) {
        this.httpClient = HttpClient.newBuilder()
            .sslContext(sslContext)
            .build();
    }
    // Implements GetBuilder, PostBuilder, DeleteBuilder
}
```

This is necessary because:
- `JdkA2AHttpClient` creates its own `HttpClient` internally without SSL customization
- `A2AHttpClientFactory` SPI doesn't pass configuration parameters
- The adapter pattern provides a clean way to inject our SSL configuration

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
| `HttpClientA2AAdapter` | A2AHttpClient implementation with custom SSLContext |
| `AnsVerifiedClient` | High-level client with SCITT support and mTLS |
| `AnsConnection` | Connection handle for SCITT verification flow |
| `AnsVerifiedSslContextFactory` | Creates SSLContext with certificate capture |
| `CertificateCapturingTrustManager` | Stores certificates during TLS handshake |
| `DefaultConnectionVerifier` | Coordinates DANE, Badge, SCITT verification |
| `TransparencyClient` | Fetches SCITT artifacts and root public key |

## Dependencies

```kotlin
dependencies {
    implementation("io.github.a2asdk:a2a-java-sdk-client:1.0.0.Alpha1")
    implementation("io.github.a2asdk:a2a-java-sdk-client-transport-jsonrpc:1.0.0.Alpha1")
    implementation("io.github.a2asdk:a2a-java-sdk-http-client:1.0.0.Alpha1")
    implementation("io.github.a2asdk:a2a-java-sdk-spec:1.0.0.Alpha1")
    implementation(project(":ans-sdk-agent-client"))
}
```
