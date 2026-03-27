# Spring Boot MCP Server Example

This example demonstrates a production-ready ANS-verifiable MCP server using Spring Boot 3.x,
featuring automatic SCITT artifact refresh and client request verification.

## Overview

This Spring Boot example:

- **Automatically refreshes** status tokens before they expire using `ScittArtifactManager`
- **Verifies incoming client requests** using `DefaultClientRequestVerifier`
- **Adds SCITT headers** to all responses for client verification
- **Exposes health status** via Spring Actuator endpoints
- **Supports configurable verification policies** via `application.yml`

## Usage

```bash
# Set required environment variables
export ANS_AGENT_ID=your-agent-uuid
export SSL_KEYSTORE_PATH=/path/to/keystore.p12
export SSL_KEYSTORE_PASSWORD=changeit
export SSL_TRUSTSTORE_PATH=/path/to/truststore.p12
export SSL_TRUSTSTORE_PASSWORD=changeit

# Run the server
./gradlew :ans-sdk-agent-client:examples:mcp-server-spring:bootRun

# Or run with custom properties
./gradlew :ans-sdk-agent-client:examples:mcp-server-spring:bootRun \
  --args="--ans.mcp.verification.policy=SCITT_REQUIRED"
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Spring Boot Server                      │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────┐    ┌─────────────────────────┐     │
│  │ ClientVerification  │───▶│ ScittHeaderResponse     │     │
│  │ Filter (FIRST)      │    │ Filter (LAST)           │     │
│  └─────────────────────┘    └─────────────────────────┘     │
│           │                            │                    │
│           ▼                            ▼                    │
│  ┌─────────────────────┐    ┌─────────────────────────┐     │
│  │ DefaultClient       │    │ ScittArtifactManager    │     │
│  │ RequestVerifier     │    │ (cached raw bytes)      │     │
│  └─────────────────────┘    └─────────────────────────┘     │
│           │                            │                    │
│           ▼                            ▼                    │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              TransparencyClient                     │    │
│  │         (fetches artifacts, root key)               │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Key Features

### 1. Automatic SCITT Artifact Refresh

```java
// ScittLifecycle.java starts background refresh on startup
@Override
public void start() {
    // Fetch initial artifacts
    artifactManager.getReceipt(agentId).join();
    artifactManager.getStatusToken(agentId).join();

    // Start background refresh at (exp - iat) / 2 intervals
    artifactManager.startBackgroundRefresh(agentId);
}
```

Tokens are refreshed automatically, ensuring they never expire during operation:
- **Receipts**: Cached indefinitely (immutable Merkle proofs)
- **Status tokens**: Refreshed at `(exp - iat) / 2` intervals

### 2. Client Request Verification

```java
// ClientVerificationFilter.java delegates to DefaultClientRequestVerifier
ClientRequestVerificationResult result = verifier
    .verify(clientCert, headers, policy)
    .get(5, TimeUnit.SECONDS);

if (!result.verified()) {
    if (policy.scittMode() == VerificationMode.REQUIRED) {
        response.sendError(403, "Client verification failed: " + result.errors());
        return;
    }
    // Advisory mode - log warning but continue
}

// Store verified agent ID for downstream use
request.setAttribute("ans.verified.agentId", result.agentId());
```

Security features provided by `DefaultClientRequestVerifier`:
- 64KB header size limit (DoS protection)
- Constant-time fingerprint comparison (timing attack protection)
- Result caching by `sha256(receipt):sha256(token):certFingerprint`
- Uses `validIdentityCertFingerprints()` for client verification

### 3. SCITT Response Headers

```java
// ScittHeaderResponseFilter.java adds headers to all responses
byte[] receiptBytes = artifactManager.getReceiptBytes(agentId)
    .get(5, TimeUnit.SECONDS);
byte[] tokenBytes = artifactManager.getStatusTokenBytes(agentId)
    .get(5, TimeUnit.SECONDS);

if (receiptBytes != null) {
    response.addHeader("X-SCITT-Receipt", Base64.getEncoder().encodeToString(receiptBytes));
}
if (tokenBytes != null) {
    response.addHeader("X-ANS-Status-Token", Base64.getEncoder().encodeToString(tokenBytes));
}
```

### 4. Health Monitoring

```bash
curl -k https://localhost:8443/actuator/health
```

```json
{
  "status": "UP",
  "components": {
    "scitt": {
      "status": "UP",
      "details": {
        "agentId": "abc-123",
        "tokenStatus": "ACTIVE",
        "tokenExpiration": "2024-01-15T10:30:00Z",
        "timeRemaining": "2h 30m 15s",
        "stale": false
      }
    }
  }
}
```

## Configuration

### application.yml

```yaml
server:
  port: 8443
  ssl:
    enabled: true
    key-store: ${SSL_KEYSTORE_PATH}
    key-store-password: ${SSL_KEYSTORE_PASSWORD}
    client-auth: need  # mTLS required
    trust-store: ${SSL_TRUSTSTORE_PATH}
    trust-store-password: ${SSL_TRUSTSTORE_PASSWORD}

ans:
  mcp:
    agent-id: ${ANS_AGENT_ID}
    verification:
      enabled: true
      policy: SCITT_REQUIRED  # See policies below
    scitt:
      domain: transparency.ans.godaddy.com
```

### Verification Policies

| Policy | DANE | Badge | SCITT | Description |
|--------|------|-------|-------|-------------|
| `PKI_ONLY` | - | - | - | No additional verification beyond TLS |
| `BADGE_REQUIRED` | - | ✓ | - | Require valid badge |
| `SCITT_REQUIRED` | - | - | ✓ | **Recommended** - require SCITT headers |
| `SCITT_ENHANCED` | - | advisory | ✓ | SCITT with badge fallback |
| `DANE_REQUIRED` | ✓ | - | - | Strict DANE verification |

### VerificationMode Options

| Mode | Behavior |
|------|----------|
| `DISABLED` | Skip this verification type |
| `ADVISORY` | Allow fallback if headers absent; **reject if headers present but invalid** |
| `REQUIRED` | Reject connection if verification fails or headers missing |

**Note:** ADVISORY mode still rejects invalid SCITT headers to prevent downgrade attacks where attackers send garbage headers to force badge fallback.

## Key Classes

| Class | Location | Purpose |
|-------|----------|---------|
| `ScittArtifactManager` | ans-sdk-transparency | Background refresh and caching of SCITT artifacts |
| `DefaultClientRequestVerifier` | ans-sdk-agent-client | Verifies client SCITT artifacts with security protections |
| `ClientRequestVerificationResult` | ans-sdk-agent-client | Verification outcome (verified, agentId, errors, duration) |
| `TransparencyClient` | ans-sdk-transparency | Fetches artifacts and root public key from TL |
| `ClientVerificationFilter` | example | Spring filter that extracts cert + headers, calls verifier |
| `ScittHeaderResponseFilter` | example | Spring filter that adds SCITT headers to responses |
| `ScittHealthIndicator` | example | Actuator health endpoint for SCITT status |

## How Client Verification Works

1. **Extract client certificate** from `jakarta.servlet.request.X509Certificate` (mTLS)
2. **Extract SCITT headers** (`X-SCITT-Receipt`, `X-ANS-Status-Token`) from request
3. **Check cache** - keyed by `sha256(receipt):sha256(token):certFingerprint`
4. **Verify receipt signature** - ES256 over COSE Sig_structure
5. **Verify Merkle proof** - RFC 9162 inclusion proof
6. **Verify token signature** - ES256 + expiry check with clock skew tolerance
7. **Match fingerprint** - client cert SHA-256 vs `validIdentityCertFingerprints()` (constant-time)
8. **Return result** - includes `agentId`, `statusToken`, `receipt`, verification duration

## Prerequisites

- Java 17+
- Valid SSL keystore with server certificate
- Truststore with trusted client CA certificates
- Agent registered in ANS transparency log
- For client verification: Clients must include SCITT headers

## Testing with MCP Client

```bash
# Terminal 1: Start Spring server
./gradlew :ans-sdk-agent-client:examples:mcp-server-spring:bootRun

# Terminal 2: Run client example (once server is up)
./gradlew :ans-sdk-agent-client:examples:mcp-client:run \
  --args="https://localhost:8443/mcp"
```

## Dependencies

```kotlin
dependencies {
    implementation(platform("org.springframework.boot:spring-boot-dependencies:3.2.5"))
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("io.modelcontextprotocol.sdk:mcp:1.1.0")
    implementation(project(":ans-sdk-agent-client"))
    implementation(project(":ans-sdk-transparency"))
}
```

## Security Considerations

- **DoS protection**: 64KB header size limit prevents memory exhaustion
- **Timing attacks**: Constant-time `MessageDigest.isEqual()` for fingerprint comparison
- **Cache efficiency**: Results cached to avoid redundant crypto operations
- **Downgrade protection**: `SCITT_REQUIRED` policy prevents stripping headers to force badge fallback
- **mTLS required**: `client-auth: need` ensures mutual authentication