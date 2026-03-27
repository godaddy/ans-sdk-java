# ANS Java SDK

Java SDK for the Agent Name Service (ANS) Registry. This SDK provides clients for agent registration, discovery, and secure agent-to-agent communication.

## API Specification Reference

The ANS Registry SDK is based off of the REST API. The spec is documented using the OpenAPI (Swagger) specification:
- [View OpenAPI Spec - Human Readable](https://developer.godaddy.com/doc/endpoint/ans)
- [OpenAPI Spec - AI/Machine Readable](https://developer.godaddy.com/swagger/swagger_ans.json)

## Requirements

- Java 17 or higher
- Gradle 8.5+ (for building from source)

## Modules

| Module | Description                                           |
|--------|-------------------------------------------------------|
| `ans-sdk-core` | Configuration, authentication, and shared utilities   |
| `ans-sdk-crypto` | Key pair generation and CSR creation                  |
| `ans-sdk-api` | Generated models from OpenAPI specification           |
| `ans-sdk-registration` | Agent registration and verification                   |
| `ans-sdk-discovery` | Agent resolution by hostname and version              |
| `ans-sdk-agent-client` | Secure agent-to-agent connections with trust policies |

## Installation

### Gradle

```kotlin
dependencies {
    // For agent registration
    implementation("com.godaddy.ans:ans-sdk-registration:0.1.0")

    // For agent discovery/resolution
    implementation("com.godaddy.ans:ans-sdk-discovery:0.1.0")

    // For agent-to-agent connections
    implementation("com.godaddy.ans:ans-sdk-agent-client:0.1.0")

    // For cryptographic operations (key generation, CSRs)
    implementation("com.godaddy.ans:ans-sdk-crypto:0.1.0")
}
```

### Maven

```xml
<dependency>
    <groupId>com.godaddy.ans</groupId>
    <artifactId>ans-sdk-registration</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Quick Start

### Agent Registration

The registration flow involves registering your agent and completing ACME and DNS verification. You have two options for the server TLS certificate:

1. **CSR Flow** (Recommended): Submit a CSR and let ANS issue the certificate
2. **BYOC Flow**: Bring Your Own Certificate (e.g., from Let's Encrypt)

Both flows require an identity CSR - the ANS-issued identity certificate contains your agent's ANS name.

#### Option 1: CSR Flow (ANS-Issued Certificates)

```java
import com.godaddy.ans.sdk.registration.RegistrationClient;
import com.godaddy.ans.sdk.auth.ApiKeyCredentialsProvider;
import com.godaddy.ans.sdk.config.Environment;
import com.godaddy.ans.sdk.crypto.KeyPairManager;
import com.godaddy.ans.sdk.crypto.CsrGenerator;
import com.godaddy.ans.sdk.model.generated.*;

import java.net.URI;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;

// === Step 1: Generate Key Pairs ===
String agentHost = "my-agent.example.com";
String version = "1.0.0";

KeyPairManager keyManager = new KeyPairManager();
KeyPair identityKeyPair = keyManager.generateRsaKeyPair(2048);
KeyPair serverKeyPair = keyManager.generateRsaKeyPair(2048);

// Save keys for later use when certificates are issued
Path keysDir = Path.of("keys", agentHost);
keyManager.savePrivateKeyToPem(identityKeyPair, keysDir.resolve("identity-private.pem"), null);
keyManager.savePrivateKeyToPem(serverKeyPair, keysDir.resolve("server-private.pem"), null);

// === Step 2: Generate CSRs ===
CsrGenerator csrGenerator = new CsrGenerator();

// Server CSR: for TLS certificate (CN + SAN DNS)
String serverCsr = csrGenerator.generateServerCsr(serverKeyPair, agentHost);

// Identity CSR: includes ANS URI in SAN (ans://v{version}.{agentHost})
String identityCsr = csrGenerator.generateIdentityCsr(identityKeyPair, agentHost, version);

// === Step 3: Build Registration Request ===
AgentEndpoint a2aEndpoint = new AgentEndpoint()
    .protocol(Protocol.A2A)
    .agentUrl(URI.create("https://" + agentHost + "/a2a"))
    .addFunctionsItem(new AgentFunction()
        .name("HealthCheck")
        .id("health-check")
        .tags(List.of("health", "diagnostics")));

AgentRegistrationRequest request = new AgentRegistrationRequest()
    .agentHost(agentHost)
    .agentDisplayName("My Agent")
    .agentDescription("An example agent")
    .version(version)
    .addEndpointsItem(a2aEndpoint)
    .identityCsrPEM(identityCsr)   // Required: identity certificate CSR
    .serverCsrPEM(serverCsr);       // Server CSR (ANS issues the certificate)

// === Step 4: Register the Agent ===
RegistrationClient client = RegistrationClient.builder()
    .environment(Environment.OTE)
    .credentialsProvider(new ApiKeyCredentialsProvider(apiKey, apiSecret))
    .build();

AgentDetails agentDetails = client.registerAgent(request);
String agentId = agentDetails.getAgentId();

System.out.println("Agent ID: " + agentId);
System.out.println("Status: " + agentDetails.getAgentStatus());

// === Step 5: Handle ACME Challenge ===
// The response includes ACME DNS challenge details
RegistrationPending pending = agentDetails.getRegistrationPending();
if (pending != null && pending.getChallenges() != null) {
    for (ChallengeInfo challenge : pending.getChallenges()) {
        System.out.println("Add DNS TXT record:");
        System.out.println("  Name: " + challenge.getDnsRecord());
        System.out.println("  Value: " + challenge.getToken());
    }
}

// After adding the ACME DNS TXT record, trigger verification
// Poll until status changes from PENDING_VALIDATION to PENDING_DNS
AgentStatus status = client.verifyAcme(agentId);
while (status.getStatus() == AgentLifecycleStatus.PENDING_VALIDATION) {
    Thread.sleep(60000); // Wait 60 seconds
    status = client.verifyAcme(agentId);
}

// === Step 6: Wait for Certificate Issuance ===
// After ACME verification, status changes to PENDING_CERTS while certificates are issued.
// During this time, nextSteps will show: Action=WAIT, Description="Waiting for certificate issuance"
// Poll until status becomes PENDING_DNS (certificates issued, DNS records available)
System.out.println("ACME verified. Waiting for certificate issuance...");
agentDetails = client.getAgent(agentId);
while (agentDetails.getAgentStatus().equals("PENDING_CERTS")) {
    Thread.sleep(30000); // Wait 30 seconds
    agentDetails = client.getAgent(agentId);

    // Check nextSteps for status updates
    pending = agentDetails.getRegistrationPending();
    if (pending != null && pending.getNextSteps() != null) {
        for (NextStep step : pending.getNextSteps()) {
            System.out.println("Status: " + step.getAction() + " - " + step.getDescription());
        }
    }
}

// === Step 7: Handle DNS Verification ===
// Once status is PENDING_DNS, certificates are issued and DNS records are available
agentDetails = client.getAgent(agentId);
pending = agentDetails.getRegistrationPending();

if (pending != null && pending.getDnsRecords() != null) {
    System.out.println("Add these DNS records:");
    for (DnsRecord record : pending.getDnsRecords()) {
        System.out.println("  Type: " + record.getType());
        System.out.println("  Name: " + record.getName());
        System.out.println("  Value: " + record.getValue());
    }
}

// After adding DNS records, trigger verification
// Poll until status becomes ACTIVE
status = client.verifyDns(agentId);
while (status.getStatus() == AgentLifecycleStatus.PENDING_DNS) {
    Thread.sleep(60000); // Wait 60 seconds
    status = client.verifyDns(agentId);
}

if (status.getStatus() == AgentLifecycleStatus.ACTIVE) {
    System.out.println("Registration complete! Agent is now ACTIVE.");
}
```

#### Registration Flow Summary

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Generate Keys  │───▶│  Generate CSRs  │───▶│    Register     │
│  & Save to PEM  │    │(Server+Identity)│    │   (with CSRs)   │
└─────────────────┘    └─────────────────┘    └────────┬────────┘
                                                       │
                                                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     ACTIVE      │◀───│  DNS Verify     │◀───│  ACME Verify    │
│  (Discoverable) │    │ (TLSA records)  │    │ (TXT challenge) │
└─────────────────┘    └────────┬────────┘    └────────┬────────┘
                                │                      │
                                │              ┌───────┴───────┐
                                │              │ Wait for Cert │
                                │◀─────────────│   Issuance    │
                                               └───────────────┘
```

1. **Generate Keys**: Create RSA or EC key pairs for identity and server certificates
2. **Generate CSRs**: Create certificate signing requests for both certificates
3. **Submit Registration**: Include CSRs in the registration request
4. **ACME Verification**: Add the DNS TXT record for domain ownership proof
5. **Certificate Issuance**: Wait while certificates are generated (poll until PENDING_DNS)
6. **DNS Verification**: Add TLSA and other required DNS records
7. **Active**: Agent is registered and discoverable

#### Option 2: BYOC Flow (Bring Your Own Certificate)

If you already have a valid TLS certificate for your domain (e.g., from Let's Encrypt, DigiCert, or your own CA), you can use BYOC instead of having ANS issue a server certificate. You still need an identity CSR since the identity certificate must be issued by ANS.

```java
import com.godaddy.ans.sdk.registration.RegistrationClient;
import com.godaddy.ans.sdk.auth.ApiKeyCredentialsProvider;
import com.godaddy.ans.sdk.config.Environment;
import com.godaddy.ans.sdk.crypto.KeyPairManager;
import com.godaddy.ans.sdk.crypto.CsrGenerator;
import com.godaddy.ans.sdk.model.generated.*;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;

String agentHost = "my-agent.example.com";
String version = "1.0.0";

// === Step 1: Generate Identity Key Pair and CSR ===
// (Identity certificate must always be issued by ANS)
KeyPairManager keyManager = new KeyPairManager();
KeyPair identityKeyPair = keyManager.generateRsaKeyPair(2048);
keyManager.savePrivateKeyToPem(identityKeyPair, Path.of("keys/identity-private.pem"), null);

CsrGenerator csrGenerator = new CsrGenerator();
String identityCsr = csrGenerator.generateIdentityCsr(identityKeyPair, agentHost, version);

// === Step 2: Load Your Existing Server Certificate ===
// These are your existing certificates (e.g., from Let's Encrypt)
String serverCertPem = Files.readString(Path.of("/etc/letsencrypt/live/" + agentHost + "/cert.pem"));
String serverChainPem = Files.readString(Path.of("/etc/letsencrypt/live/" + agentHost + "/chain.pem"));

// === Step 3: Build Registration Request with BYOC ===
AgentEndpoint a2aEndpoint = new AgentEndpoint()
    .protocol(Protocol.A2A)
    .agentUrl(URI.create("https://" + agentHost + "/a2a"));

AgentRegistrationRequest request = new AgentRegistrationRequest()
    .agentHost(agentHost)
    .agentDisplayName("My Agent")
    .version(version)
    .addEndpointsItem(a2aEndpoint)
    .identityCsrPEM(identityCsr)            // Required: identity certificate CSR
    .serverCertificatePEM(serverCertPem)     // BYOC: your server certificate
    .serverCertificateChainPEM(serverChainPem); // BYOC: certificate chain

// === Step 4: Register and Complete Verification ===
RegistrationClient client = RegistrationClient.builder()
    .environment(Environment.OTE)
    .credentialsProvider(new ApiKeyCredentialsProvider(apiKey, apiSecret))
    .build();

AgentDetails agentDetails = client.registerAgent(request);
// ... continue with ACME and DNS verification as shown above
```

**Key differences with BYOC:**
- Use `serverCertificatePEM` instead of `serverCsrPEM`
- Include `serverCertificateChainPEM` with the certificate chain
- You skip the "Wait for Certificate Issuance" step for the server certificate
- You're responsible for renewing your server certificate before it expires

### Agent Discovery

Resolve an agent by hostname and version:

```java
import com.godaddy.ans.sdk.discovery.DiscoveryClient;
import com.godaddy.ans.sdk.auth.JwtCredentialsProvider;
import com.godaddy.ans.sdk.config.Environment;

// Create the discovery client
DiscoveryClient client = DiscoveryClient.builder()
    .environment(Environment.PROD)
    .credentialsProvider(new JwtCredentialsProvider(jwtToken))
    .build();

// Resolve by hostname with version constraint
AgentDetails agent = client.resolve("booking-agent.example.com", "^1.0.0");
System.out.println("Found: " + agent.getAnsName());
System.out.println("Endpoints: " + agent.getEndpoints());

// Resolve latest version
AgentDetails latest = client.resolve("booking-agent.example.com");

// Get agent by ID
AgentDetails byId = client.getAgent("550e8400-e29b-41d4-a716-446655440000");

// Async resolution
CompletableFuture<AgentDetails> future = client.resolveAsync("booking-agent.example.com");
```

### Agent-to-Agent Connections

Connect to another agent with configurable verification levels:

```java
import com.godaddy.ans.sdk.agent.AnsClient;
import com.godaddy.ans.sdk.agent.ConnectOptions;
import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.agent.connection.AgentConnection;

// Create the client
AnsClient client = AnsClient.create();

// PKI only - standard HTTPS with CA validation
AgentConnection conn = client.connect("https://target-agent.example.com");

// Badge verification (recommended) - verifies against transparency log
AgentConnection conn = client.connect("https://target-agent.example.com",
    ConnectOptions.builder()
        .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
        .build());

// Full verification - DANE + Badge
AgentConnection conn = client.connect("https://target-agent.example.com",
    ConnectOptions.builder()
        .verificationPolicy(VerificationPolicy.DANE_AND_BADGE)
        .build());

// With mTLS client certificate
AgentConnection conn = client.connect("https://target-agent.example.com",
    ConnectOptions.builder()
        .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
        .clientCertPath(Path.of("/path/to/cert.pem"), Path.of("/path/to/key.pem"))
        .build());

// Make API calls
String response = conn.httpApiAt("https://target-agent.example.com")
    .get("/api/v1/data");

// Or with automatic deserialization
MyResponse response = conn.httpApiAt("https://target-agent.example.com")
    .get("/api/v1/data", MyResponse.class);
```

### Key Generation and CSRs

Generate key pairs and certificate signing requests:

```java
import com.godaddy.ans.sdk.crypto.KeyPairManager;
import com.godaddy.ans.sdk.crypto.CsrGenerator;

KeyPairManager keyManager = new KeyPairManager();
CsrGenerator csrGenerator = new CsrGenerator();

// Generate RSA key pair
KeyPair keyPair = keyManager.generateRsaKeyPair(2048);

// Or EC key pair
KeyPair ecKeyPair = keyManager.generateEcKeyPair("secp256r1");

// Save private key (encrypted)
keyManager.savePrivateKeyToPem(keyPair, Path.of("private.pem"), "password");

// Save private key (unencrypted)
keyManager.savePrivateKeyToPem(keyPair, Path.of("private.pem"), null);

// Load key pair from file
KeyPair loaded = keyManager.loadKeyPairFromPem(Path.of("private.pem"), "password");

// Generate server certificate CSR
String serverCsr = csrGenerator.generateServerCsr(
    keyPair,
    "my-agent.example.com",           // Common Name
    List.of("my-agent.example.com")   // Subject Alternative Names
);

// Generate identity certificate CSR (includes ANS URI in SAN)
String identityCsr = csrGenerator.generateIdentityCsr(
    keyPair,
    "my-agent.example.com",
    "1.0.0"  // Version for ANS name
);
```

## Verification Policies

The SDK supports verification levels for agent-to-agent connections:

| Policy | Verification | Use Case |
|--------|--------------|----------|
| **PKI_ONLY** | Standard HTTPS with system CA validation | Development, internal networks |
| **DANE_REQUIRED** | PKI + DANE/TLSA DNS record verification | Production with DNS-based trust |
| **BADGE_REQUIRED** | PKI + Transparency log verification | Recommended for most use cases |
| **FULL** | PKI + DANE + Badge verification | Maximum security |

### Verification Sequence Diagrams

#### PKI-Only: Standard TLS

```
┌────────┐                              ┌────────────┐                    ┌────────────┐
│ Client │                              │   Server   │                    │ System CA  │
└───┬────┘                              └─────┬──────┘                    │Trust Store │
    │                                         │                           └─────┬──────┘
    │  1. TLS Handshake (ClientHello)         │                                 │
    │────────────────────────────────────────▶│                                 │
    │                                         │                                 │
    │  2. ServerHello + Certificate Chain     │                                 │
    │◀────────────────────────────────────────│                                 │
    │                                         │                                 │
    │  3. Validate cert chain against CA store│                                 │
    │─────────────────────────────────────────────────────────────────────────▶│
    │                                         │                                 │
    │  4. Chain valid ✓                       │                                 │
    │◀─────────────────────────────────────────────────────────────────────────│
    │                                         │                                 │
    │  5. Complete TLS Handshake              │                                 │
    │◀───────────────────────────────────────▶│                                 │
    │                                         │                                 │
    │  6. Encrypted Application Data          │                                 │
    │◀═══════════════════════════════════════▶│                                 │
```

#### DANE_REQUIRED: TLS + DANE Verification

```
┌────────┐                    ┌─────────────┐        ┌────────────┐        ┌────────────┐
│ Client │                    │ DNS Server  │        │   Server   │        │ System CA  │
└───┬────┘                    └──────┬──────┘        └─────┬──────┘        └─────┬──────┘
    │                                │                     │                     │
    │  1. Query TLSA record          │                     │                     │
    │   _443._tcp.agent.example.com  │                     │                     │
    │───────────────────────────────▶│                     │                     │
    │                                │                     │                     │
    │  2. TLSA: 3 1 1 <cert-hash>    │                     │                     │
    │◀───────────────────────────────│                     │                     │
    │                                │                     │                     │
    │  3. TLS Handshake              │                     │                     │
    │─────────────────────────────────────────────────────▶│                     │
    │                                │                     │                     │
    │  4. Certificate Chain          │                     │                     │
    │◀─────────────────────────────────────────────────────│                     │
    │                                │                     │                     │
    │  5. Validate against CA store  │                     │                     │
    │────────────────────────────────────────────────────────────────────────────▶
    │                                │                     │                     │
    │  6. Compute SHA-256 of server cert                   │                     │
    │  7. Compare hash with TLSA record                    │                     │
    │     ┌─────────────────────────────────┐              │                     │
    │     │ cert_hash == TLSA_hash ? ✓      │              │                     │
    │     └─────────────────────────────────┘              │                     │
    │                                │                     │                     │
    │  8. DANE Verified ✓            │                     │                     │
    │                                │                     │                     │
    │  9. Complete TLS + Send Data   │                     │                     │
    │◀════════════════════════════════════════════════════▶│                     │
```

### DANE/TLSA Verification

DANE verification ensures that the server's TLS certificate matches a TLSA DNS record published at `_443._tcp.hostname`.

```java
// Require DANE verification (fail if no TLSA record)
ConnectOptions.builder()
    .verificationPolicy(VerificationPolicy.DANE_REQUIRED)
    .build();

// DANE in advisory mode (warn but continue if no TLSA record)
ConnectOptions.builder()
    .verificationPolicy(VerificationPolicy.DANE_ADVISORY)
    .build();
```

### Badge Verification

Badge verification checks the ANS transparency log to confirm the agent is registered:

```java
// Require Badge verification (recommended)
ConnectOptions.builder()
    .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
    .build();

// Full verification (DANE + Badge)
ConnectOptions.builder()
    .verificationPolicy(VerificationPolicy.DANE_AND_BADGE)
    .build();
```

## Configuration

### Environment

```java
// OTE (testing environment)
.environment(Environment.OTE)  // https://api.ote-godaddy.com

// Production
.environment(Environment.PROD)  // https://api.godaddy.com

// Custom URL
.baseUrl("https://custom-api.example.com")
```

### Authentication

```java
// JWT token authentication
.credentialsProvider(new JwtCredentialsProvider(jwtToken))

// API key authentication
.credentialsProvider(new ApiKeyCredentialsProvider(apiKey, apiSecret))

// Environment variables (ANS_JWT_TOKEN or ANS_API_KEY + ANS_API_SECRET)
.credentialsProvider(new EnvironmentCredentialsProvider())

// Refreshable JWT (for long-running processes)
.credentialsProvider(new RefreshableJwtCredentialsProvider(() -> fetchNewToken()))
```

### Timeouts and Retries

```java
DiscoveryClient client = DiscoveryClient.builder()
    .environment(Environment.PROD)
    .credentialsProvider(credentials)
    .connectTimeout(Duration.ofSeconds(5))
    .readTimeout(Duration.ofSeconds(30))
    .enableRetry(3)  // Max 3 retry attempts
    .build();
```

## Error Handling

The SDK uses a hierarchy of exceptions for different error types:

```java
try {
    AgentDetails agent = client.resolve("unknown-agent.example.com");
} catch (AnsNotFoundException e) {
    // Agent not found (404)
    System.err.println("Agent not found: " + e.getMessage());
} catch (AnsAuthenticationException e) {
    // Authentication failed (401/403)
    System.err.println("Auth error: " + e.getMessage());
} catch (AnsValidationException e) {
    // Validation error (422)
    System.err.println("Invalid request: " + e.getMessage());
} catch (AnsServerException e) {
    // Server error (5xx)
    System.err.println("Server error: " + e.getMessage());
    System.err.println("Request ID: " + e.getRequestId());
} catch (AnsException e) {
    // Any other SDK error
    System.err.println("Error: " + e.getMessage());
}
```

## Building from Source

```bash
# Build all modules
./gradlew build

# Run tests
./gradlew test

# Build without tests
./gradlew build -x test
```

## Version Constraints

When resolving agents, you can use semantic version constraints:

| Constraint | Matches |
|------------|---------|
| `1.2.3` | Exact version 1.2.3 |
| `^1.2.0` | Compatible with 1.2.0 (>=1.2.0 <2.0.0) |
| `~1.2.0` | Approximately 1.2.0 (>=1.2.0 <1.3.0) |
| `*` | Any version (latest) |

```java
client.resolve("agent.example.com", "^1.0.0");  // Any 1.x version
client.resolve("agent.example.com", "~1.2.0");  // Any 1.2.x version
client.resolve("agent.example.com");            // Latest version
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on
how to get involved, including commit message conventions, code review process, and more.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.