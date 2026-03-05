# A2A Client Example

This example demonstrates ANS verification integration with the official
[A2A (Agent-to-Agent) Java SDK](https://github.com/a2aprotocol/a2a-java).

## Overview

The A2A SDK's built-in `JdkA2AHttpClient` doesn't expose SSL customization, so this
example includes an `HttpClientA2AAdapter` that implements `A2AHttpClient` with a custom
`SSLContext` for ANS certificate capture.

## Prerequisites

- A2A server with HTTPS endpoint (implements `/.well-known/agent-card.json`)
- For Badge verification: Agent in ANS transparency log
- For DANE verification: TLSA DNS records configured

## Usage

```bash
# Run with default settings
./gradlew :ans-sdk-agent-client:examples:a2a-client:run

# Run with custom server URL
./gradlew :ans-sdk-agent-client:examples:a2a-client:run --args="https://your-a2a-server.example.com:8443"
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

// 4. Create A2A HTTP client adapter with custom SSLContext
HttpClientA2AAdapter httpClient = new HttpClientA2AAdapter(sslContext);

// 5. Fetch AgentCard (triggers TLS handshake)
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

## Key Classes

| Class | Purpose |
|-------|---------|
| `HttpClientA2AAdapter` | A2AHttpClient implementation with custom SSLContext |
| `AnsVerifiedSslContextFactory` | Creates SSLContext with certificate capture |
| `CertificateCapturingTrustManager` | Stores certificates during TLS handshake |
| `DefaultConnectionVerifier` | Coordinates DANE, Badge verification |

## Dependencies

```kotlin
dependencies {
    implementation("io.github.a2asdk:a2a-java-sdk-client:1.0.0.Alpha1")
    implementation("io.github.a2asdk:a2a-java-sdk-client-transport-jsonrpc:1.0.0.Alpha1")
    implementation("io.github.a2asdk:a2a-java-sdk-http-client:1.0.0.Alpha1")
    implementation("io.github.a2asdk:a2a-java-sdk-spec:1.0.0.Alpha1")
}
```