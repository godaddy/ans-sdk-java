# HTTP API Example

This example demonstrates ANS verification using the `AnsClient` high-level API.

## Overview

The `AnsClient` provides a simple builder-based API for connecting to ANS-registered agents
with various verification policies. This is the recommended approach for most use cases.

## Usage

```bash
# Run with default settings
./gradlew :ans-sdk-agent-client:examples:http-api:run

# Run with custom server URL
./gradlew :ans-sdk-agent-client:examples:http-api:run --args="https://your-agent.example.com:8443"
```

## Code Highlights

### Basic Connection (PKI_ONLY)

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

### Badge Verification (Recommended)

```java
ConnectOptions options = ConnectOptions.builder()
    .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
    .build();

AgentConnection conn = client.connect(serverUrl, options);
```

### Custom Policy (DANE Advisory + Badge Required)

```java
VerificationPolicy customPolicy = VerificationPolicy.custom()
    .dane(VerificationMode.ADVISORY)
    .badge(VerificationMode.REQUIRED)
    .build();

ConnectOptions options = ConnectOptions.builder()
    .verificationPolicy(customPolicy)
    .build();

AgentConnection conn = client.connect(serverUrl, options);
```

## Verification Policies

| Policy | Description | Use Case |
|--------|-------------|----------|
| `PKI_ONLY` | System trust store only | Development, testing |
| `DANE_REQUIRED` | Requires DANE/TLSA | High security with DNSSEC |
| `BADGE_REQUIRED` | Requires transparency log | **Recommended for production** |
| `DANE_AND_BADGE` | Both DANE and Badge | Maximum security |
| `FULL` | DANE + Badge | Maximum security |

## Prerequisites

- ANS-registered agent with HTTPS endpoint
- For Badge verification: Agent in ANS transparency log
- For DANE verification: TLSA DNS records configured