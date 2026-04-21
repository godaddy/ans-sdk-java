package com.godaddy.ans.sdk.agent;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.godaddy.ans.sdk.transparency.TransparencyClient;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.FileOutputStream;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.head;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AnsVerifiedClientTest {

    @TempDir
    Path tempDir;

    @Mock
    private TransparencyClient mockTransparencyClient;

    @org.junit.jupiter.api.BeforeEach
    void setUp() {
        lenient().when(mockTransparencyClient.getBaseUrl())
            .thenReturn("https://transparency.test.example.com");
    }

    @Nested
    @DisplayName("Builder tests")
    class BuilderTests {

        @Test
        @DisplayName("Should create client with defaults")
        void shouldCreateClientWithDefaults() throws Exception {
            // Create a minimal PKCS12 keystore for testing
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .build();

            assertThat(client).isNotNull();
            assertThat(client.sslContext()).isNotNull();
            assertThat(client.policy()).isEqualTo(VerificationPolicy.SCITT_REQUIRED);
            assertThat(client.fetchScittHeadersAsync().join()).isEmpty(); // No agent ID set
            client.close();
        }

        @Test
        @DisplayName("Should use provided policy")
        void shouldUseProvidedPolicy() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.PKI_ONLY)
                .build();

            assertThat(client.policy()).isEqualTo(VerificationPolicy.PKI_ONLY);
            client.close();
        }

        @Test
        @DisplayName("Should throw on invalid keystore path")
        void shouldThrowOnInvalidKeystorePath() {
            assertThatThrownBy(() -> AnsVerifiedClient.builder()
                .keyStorePath("/nonexistent/path.p12", "password")
                .transparencyClient(mockTransparencyClient)
                .build())
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Failed to load keystore");
        }

        @Test
        @DisplayName("Should load keystore from path")
        void shouldLoadKeystoreFromPath() throws Exception {
            // Create a PKCS12 keystore file
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "testpass".toCharArray());
            Path keystorePath = tempDir.resolve("test.p12");
            try (FileOutputStream fos = new FileOutputStream(keystorePath.toFile())) {
                keyStore.store(fos, "testpass".toCharArray());
            }

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .keyStorePath(keystorePath.toString(), "testpass")
                .transparencyClient(mockTransparencyClient)
                .build();

            assertThat(client.sslContext()).isNotNull();
            client.close();
        }

        @Test
        @DisplayName("Should set connect timeout")
        void shouldSetConnectTimeout() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            // Just verify it doesn't throw
            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .connectTimeout(Duration.ofSeconds(15))
                .build();

            assertThat(client).isNotNull();
            client.close();
        }

        @Test
        @DisplayName("Should set agent ID")
        void shouldSetAgentIdButNotFetchWithoutScitt() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            // With PKI_ONLY, SCITT is disabled so no headers will be fetched
            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .agentId("test-agent-123")
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.PKI_ONLY)
                .build();

            assertThat(client.fetchScittHeadersAsync().join()).isEmpty();
            client.close();
        }

        @Test
        @DisplayName("Should fetch SCITT headers when SCITT enabled and agentId provided")
        void shouldFetchScittHeadersWhenEnabled() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            byte[] mockReceipt = new byte[]{0x01, 0x02, 0x03};
            byte[] mockToken = new byte[]{0x04, 0x05, 0x06};
            // Mock async methods used for parallel fetch
            when(mockTransparencyClient.getReceiptAsync(anyString()))
                .thenReturn(CompletableFuture.completedFuture(mockReceipt));
            when(mockTransparencyClient.getStatusTokenAsync(anyString()))
                .thenReturn(CompletableFuture.completedFuture(mockToken));

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .agentId("test-agent-123")
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.SCITT_REQUIRED)
                .build();

            assertThat(client.fetchScittHeadersAsync().join()).isNotEmpty();
            assertThat(client.fetchScittHeadersAsync().join()).containsKey("x-scitt-receipt");
            assertThat(client.fetchScittHeadersAsync().join()).containsKey("x-ans-status-token");
            client.close();
        }

        @Test
        @DisplayName("Should handle SCITT fetch failure gracefully")
        void shouldHandleScittFetchFailure() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            // Mock async methods - receipt fails, token succeeds (but failure should propagate)
            when(mockTransparencyClient.getReceiptAsync(anyString()))
                .thenReturn(CompletableFuture.failedFuture(new RuntimeException("Failed to fetch")));
            when(mockTransparencyClient.getStatusTokenAsync(anyString()))
                .thenReturn(CompletableFuture.completedFuture(new byte[]{0x01}));

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .agentId("test-agent-123")
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.SCITT_REQUIRED)
                .build();

            // Should not throw, just have empty headers (lazy fetch fails gracefully)
            assertThat(client.fetchScittHeadersAsync().join()).isEmpty();
            client.close();
        }
    }

    @Nested
    @DisplayName("Accessor tests")
    class AccessorTests {

        @Test
        @DisplayName("transparencyClient() returns the configured client")
        void transparencyClientReturnsConfiguredClient() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .build();

            assertThat(client.transparencyClient()).isSameAs(mockTransparencyClient);
            client.close();
        }

        @Test
        @DisplayName("scittHeaders() returns immutable map")
        void scittHeadersReturnsImmutableMap() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.PKI_ONLY)
                .build();

            assertThatThrownBy(() -> client.fetchScittHeadersAsync().join().put("key", "value"))
                .isInstanceOf(UnsupportedOperationException.class);
            client.close();
        }
    }

    @Nested
    @DisplayName("scittHeadersAsync() tests")
    class ScittHeadersAsyncTests {

        @Test
        @DisplayName("Should return completed future when SCITT disabled")
        void shouldReturnCompletedFutureWhenScittDisabled() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .agentId("test-agent")
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.PKI_ONLY)
                .build();

            CompletableFuture<Map<String, String>> future = client.fetchScittHeadersAsync();
            assertThat(future).isCompletedWithValue(Map.of());
            client.close();
        }

        @Test
        @DisplayName("Should fetch headers asynchronously when SCITT enabled")
        void shouldFetchHeadersAsynchronously() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            byte[] mockReceipt = new byte[]{0x01, 0x02, 0x03};
            byte[] mockToken = new byte[]{0x04, 0x05, 0x06};
            when(mockTransparencyClient.getReceiptAsync(anyString()))
                .thenReturn(CompletableFuture.completedFuture(mockReceipt));
            when(mockTransparencyClient.getStatusTokenAsync(anyString()))
                .thenReturn(CompletableFuture.completedFuture(mockToken));

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .agentId("test-agent")
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.SCITT_REQUIRED)
                .build();

            CompletableFuture<Map<String, String>> future = client.fetchScittHeadersAsync();
            assertThat(future).succeedsWithin(Duration.ofSeconds(5));

            Map<String, String> headers = future.join();
            assertThat(headers).containsKey("x-scitt-receipt");
            assertThat(headers).containsKey("x-ans-status-token");
            client.close();
        }

        @Test
        @DisplayName("Should cache headers after first fetch")
        void shouldCacheHeadersAfterFirstFetch() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            byte[] mockReceipt = new byte[]{0x01, 0x02};
            byte[] mockToken = new byte[]{0x03, 0x04};
            when(mockTransparencyClient.getReceiptAsync(anyString()))
                .thenReturn(CompletableFuture.completedFuture(mockReceipt));
            when(mockTransparencyClient.getStatusTokenAsync(anyString()))
                .thenReturn(CompletableFuture.completedFuture(mockToken));

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .agentId("test-agent")
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.SCITT_REQUIRED)
                .build();

            // First call triggers fetch
            Map<String, String> headers1 = client.fetchScittHeadersAsync().join();
            // Second call should return cached (same instance)
            Map<String, String> headers2 = client.fetchScittHeadersAsync().join();

            assertThat(headers1).isSameAs(headers2);
            client.close();
        }

        @Test
        @DisplayName("scittHeadersAsync() returns cached result on subsequent calls")
        void scittHeadersAsyncReturnsCachedResult() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            byte[] mockReceipt = new byte[]{0x01, 0x02};
            byte[] mockToken = new byte[]{0x03, 0x04};
            when(mockTransparencyClient.getReceiptAsync(anyString()))
                .thenReturn(CompletableFuture.completedFuture(mockReceipt));
            when(mockTransparencyClient.getStatusTokenAsync(anyString()))
                .thenReturn(CompletableFuture.completedFuture(mockToken));

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .agentId("test-agent")
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.SCITT_REQUIRED)
                .build();

            // Both calls should return the same cached result
            Map<String, String> headers1 = client.fetchScittHeadersAsync().join();
            Map<String, String> headers2 = client.fetchScittHeadersAsync().join();

            assertThat(headers1).isSameAs(headers2);
            client.close();
        }
    }

    @Nested
    @DisplayName("AutoCloseable tests")
    class AutoCloseableTests {

        @Test
        @DisplayName("Should work in try-with-resources")
        void shouldWorkInTryWithResources() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            try (AnsVerifiedClient client = AnsVerifiedClient.builder()
                    .keyStore(keyStore, "password".toCharArray())
                    .transparencyClient(mockTransparencyClient)
                    .build()) {
                assertThat(client).isNotNull();
            }
            // No exception means close() worked
        }
    }

    @Nested
    @DisplayName("TransparencyClient requirement")
    class TransparencyClientRequirementTests {

        @Test
        @DisplayName("Should throw when TransparencyClient not provided")
        void shouldThrowWithoutTransparencyClient() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            // Build without providing transparencyClient - should throw
            assertThatThrownBy(() -> AnsVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .policy(VerificationPolicy.PKI_ONLY)
                .build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("TransparencyClient is required");
        }
    }

    @Nested
    @DisplayName("Verification policy configuration")
    class VerificationPolicyTests {

        @Test
        @DisplayName("BADGE_REQUIRED policy should enable badge verification")
        void badgeRequiredPolicyShouldEnableBadge() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.BADGE_REQUIRED)
                .build();

            assertThat(client.policy()).isEqualTo(VerificationPolicy.BADGE_REQUIRED);
            assertThat(client.fetchScittHeadersAsync().join()).isEmpty(); // BADGE_REQUIRED has SCITT disabled
            client.close();
        }

        @Test
        @DisplayName("DANE_REQUIRED policy should enable DANE verification")
        void daneRequiredPolicyShouldEnableDane() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.DANE_REQUIRED)
                .build();

            assertThat(client.policy()).isEqualTo(VerificationPolicy.DANE_REQUIRED);
            client.close();
        }

        @Test
        @DisplayName("SCITT_ENHANCED policy should enable SCITT with badge advisory")
        void scittEnhancedPolicyShouldEnableScittWithBadge() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            byte[] mockReceipt = new byte[]{0x07, 0x08, 0x09};
            byte[] mockToken = new byte[]{0x0A, 0x0B, 0x0C};
            when(mockTransparencyClient.getReceiptAsync(anyString()))
                .thenReturn(CompletableFuture.completedFuture(mockReceipt));
            when(mockTransparencyClient.getStatusTokenAsync(anyString()))
                .thenReturn(CompletableFuture.completedFuture(mockToken));

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .agentId("test-agent")
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.SCITT_ENHANCED)
                .build();

            assertThat(client.policy()).isEqualTo(VerificationPolicy.SCITT_ENHANCED);
            assertThat(client.fetchScittHeadersAsync().join()).isNotEmpty();
            client.close();
        }
    }

    @Nested
    @DisplayName("Agent ID edge cases")
    class AgentIdEdgeCases {

        @Test
        @DisplayName("Should not fetch SCITT headers with blank agent ID")
        void shouldNotFetchWithBlankAgentId() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .agentId("   ") // Blank
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.SCITT_REQUIRED)
                .build();

            // Should not have tried to fetch headers for blank agent ID
            assertThat(client.fetchScittHeadersAsync().join()).isEmpty();
            client.close();
        }

        @Test
        @DisplayName("Should not fetch SCITT headers with empty agent ID")
        void shouldNotFetchWithEmptyAgentId() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .agentId("") // Empty
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.SCITT_REQUIRED)
                .build();

            assertThat(client.fetchScittHeadersAsync().join()).isEmpty();
            client.close();
        }
    }

    @Nested
    @DisplayName("connect() tests")
    @WireMockTest
    class ConnectTests {

        @Test
        @DisplayName("Should connect with PKI_ONLY policy (no preflight)")
        void shouldConnectWithPkiOnly(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.PKI_ONLY)
                .build();

            String serverUrl = wmRuntimeInfo.getHttpBaseUrl() + "/mcp";
            AnsConnection connection = client.connect(serverUrl);

            assertThat(connection).isNotNull();
            assertThat(connection.hostname()).isEqualTo("localhost");
            assertThat(connection.hasScittArtifacts()).isFalse();

            connection.close();
            client.close();
        }

        @Test
        @DisplayName("SCITT_REQUIRED: should throw when no SCITT headers present")
        void scittRequiredShouldThrowWhenNoHeaders(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
            // Stub preflight to return no SCITT headers
            stubFor(head(urlEqualTo("/mcp"))
                .willReturn(aResponse()
                    .withStatus(200)));

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.SCITT_REQUIRED)
                .build();

            String serverUrl = wmRuntimeInfo.getHttpBaseUrl() + "/mcp";

            // SCITT_REQUIRED should throw when no headers present
            assertThatThrownBy(() -> client.connect(serverUrl))
                .isInstanceOf(java.util.concurrent.CompletionException.class)
                .hasCauseInstanceOf(com.godaddy.ans.sdk.agent.exception.ScittVerificationException.class);

            client.close();
        }

        @Test
        @DisplayName("SCITT_REQUIRED: should throw when SCITT headers present but invalid")
        void scittRequiredShouldThrowWhenHeadersInvalid(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
            // Stub preflight to return invalid SCITT headers (not valid COSE)
            stubFor(head(urlEqualTo("/mcp"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("X-SCITT-Receipt", "aW52YWxpZA==")  // "invalid" in base64
                    .withHeader("X-ANS-Status-Token", "aW52YWxpZA==")));

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.SCITT_REQUIRED)
                .build();

            String serverUrl = wmRuntimeInfo.getHttpBaseUrl() + "/mcp";

            // SCITT_REQUIRED should throw when headers are present but invalid
            assertThatThrownBy(() -> client.connect(serverUrl))
                .isInstanceOf(java.util.concurrent.CompletionException.class)
                .hasCauseInstanceOf(com.godaddy.ans.sdk.agent.exception.ScittVerificationException.class);

            client.close();
        }

        @Test
        @DisplayName("SCITT_FALLBACK: should allow fallback when no SCITT headers present")
        void scittFallbackShouldAllowFallbackWhenNoHeaders(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
            // Stub preflight to return no SCITT headers
            stubFor(head(urlEqualTo("/mcp"))
                .willReturn(aResponse()
                    .withStatus(200)));

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            // SCITT ADVISORY allows fallback when no headers present
            VerificationPolicy scittAdvisory = VerificationPolicy.custom()
                .scitt(VerificationMode.FALLBACK_ALLOWED)
                .build();

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(scittAdvisory)
                .build();

            String serverUrl = wmRuntimeInfo.getHttpBaseUrl() + "/mcp";
            AnsConnection connection = client.connect(serverUrl);

            // Should succeed - fallback allowed when no headers
            assertThat(connection).isNotNull();
            assertThat(connection.hasScittArtifacts()).isFalse();
            connection.close();
            client.close();
        }

        @Test
        @DisplayName("SCITT_FALLBACK: should throw when SCITT headers present but invalid")
        void scittAdvisoryShouldThrowWhenHeadersInvalid(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
            // Stub preflight to return invalid SCITT headers
            stubFor(head(urlEqualTo("/mcp"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("X-SCITT-Receipt", "aW52YWxpZA==")
                    .withHeader("X-ANS-Status-Token", "aW52YWxpZA==")));

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            // SCITT ADVISORY should reject if headers ARE present but invalid
            // (prevents attackers from sending garbage headers to force fallback)
            VerificationPolicy scittAdvisory = VerificationPolicy.custom()
                .scitt(VerificationMode.ADVISORY)
                .build();

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(scittAdvisory)
                .build();

            String serverUrl = wmRuntimeInfo.getHttpBaseUrl() + "/mcp";

            // Should throw because headers are present but invalid
            assertThatThrownBy(() -> client.connect(serverUrl))
                .isInstanceOf(java.util.concurrent.CompletionException.class)
                .hasCauseInstanceOf(com.godaddy.ans.sdk.agent.exception.ScittVerificationException.class);

            client.close();
        }

        @Test
        @DisplayName("Should parse URL with custom port")
        void shouldParseUrlWithCustomPort(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
            stubFor(head(urlEqualTo("/api"))
                .willReturn(aResponse().withStatus(200)));

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            // Use PKI_ONLY to test port parsing without SCITT verification
            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.PKI_ONLY)
                .build();

            // WireMock provides a port, which tests the port parsing
            String serverUrl = wmRuntimeInfo.getHttpBaseUrl() + "/api";
            AnsConnection connection = client.connect(serverUrl);

            assertThat(connection).isNotNull();
            assertThat(connection.hostname()).isEqualTo("localhost");

            connection.close();
            client.close();
        }

        @Test
        @DisplayName("Should include SCITT headers in preflight request")
        void shouldIncludeScittHeadersInPreflight(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
            stubFor(head(urlEqualTo("/mcp"))
                .willReturn(aResponse().withStatus(200)));

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            byte[] mockReceipt = new byte[]{0x01, 0x02};
            byte[] mockToken = new byte[]{0x03, 0x04};
            when(mockTransparencyClient.getReceiptAsync(anyString()))
                .thenReturn(CompletableFuture.completedFuture(mockReceipt));
            when(mockTransparencyClient.getStatusTokenAsync(anyString()))
                .thenReturn(CompletableFuture.completedFuture(mockToken));

            // Use SCITT ADVISORY - server returns no headers (fallback allowed)
            VerificationPolicy scittAdvisory = VerificationPolicy.custom()
                .scitt(VerificationMode.FALLBACK_ALLOWED)
                .build();

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .agentId("test-agent")
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(scittAdvisory)
                .build();

            // Verify client has SCITT headers to send
            assertThat(client.fetchScittHeadersAsync().join()).isNotEmpty();

            String serverUrl = wmRuntimeInfo.getHttpBaseUrl() + "/mcp";
            // Server returns no SCITT headers, but ADVISORY mode allows fallback
            AnsConnection connection = client.connect(serverUrl);

            assertThat(connection).isNotNull();
            connection.close();
            client.close();
        }
    }

    @Nested
    @DisplayName("connectAsync() tests")
    @WireMockTest
    class ConnectAsyncTests {

        @Test
        @DisplayName("Should return completed future with PKI_ONLY policy")
        void shouldReturnCompletedFutureWithPkiOnly(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.PKI_ONLY)
                .build();

            String serverUrl = wmRuntimeInfo.getHttpBaseUrl() + "/mcp";
            CompletableFuture<AnsConnection> future = client.connectAsync(serverUrl);

            assertThat(future).isNotNull();
            assertThat(future).succeedsWithin(Duration.ofSeconds(5));

            AnsConnection connection = future.join();
            assertThat(connection.hostname()).isEqualTo("localhost");
            assertThat(connection.hasScittArtifacts()).isFalse();

            connection.close();
            client.close();
        }

        @Test
        @DisplayName("Should fail future with malformed URL")
        void shouldFailFutureWithMalformedUrl() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.PKI_ONLY)
                .build();

            CompletableFuture<AnsConnection> future = client.connectAsync("not a valid url ://");

            assertThat(future).failsWithin(Duration.ofSeconds(1))
                .withThrowableOfType(java.util.concurrent.ExecutionException.class)
                .withCauseInstanceOf(IllegalArgumentException.class);

            client.close();
        }

        @Test
        @DisplayName("connect() should delegate to connectAsync().join()")
        void connectShouldDelegateToConnectAsync(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AnsVerifiedClient client = AnsVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.PKI_ONLY)
                .build();

            String serverUrl = wmRuntimeInfo.getHttpBaseUrl() + "/api";

            // Both methods should produce equivalent results
            AnsConnection syncConnection = client.connect(serverUrl);
            AnsConnection asyncConnection = client.connectAsync(serverUrl).join();

            assertThat(syncConnection.hostname()).isEqualTo(asyncConnection.hostname());
            assertThat(syncConnection.hasScittArtifacts()).isEqualTo(asyncConnection.hasScittArtifacts());

            syncConnection.close();
            asyncConnection.close();
            client.close();
        }
    }
}
