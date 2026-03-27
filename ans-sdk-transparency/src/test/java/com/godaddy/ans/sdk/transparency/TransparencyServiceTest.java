package com.godaddy.ans.sdk.transparency;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.godaddy.ans.sdk.exception.AnsNotFoundException;
import com.godaddy.ans.sdk.exception.AnsServerException;
import com.godaddy.ans.sdk.transparency.model.AgentAuditParams;
import com.godaddy.ans.sdk.transparency.model.CheckpointHistoryParams;
import com.godaddy.ans.sdk.transparency.model.CheckpointHistoryResponse;
import com.godaddy.ans.sdk.transparency.model.CheckpointResponse;
import com.godaddy.ans.sdk.transparency.model.TransparencyLog;
import com.godaddy.ans.sdk.transparency.model.TransparencyLogAudit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.godaddy.ans.sdk.transparency.scitt.RefreshDecision;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlMatching;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@WireMockTest
class TransparencyServiceTest {

    private static final String TEST_AGENT_ID = "test-agent-123";

    private TransparencyService createService(String baseUrl) {
        return createService(baseUrl, Duration.ofHours(24));
    }

    private TransparencyService createService(String baseUrl, Duration rootKeyCacheTtl) {
        return new TransparencyService(baseUrl, Duration.ofSeconds(5), Duration.ofSeconds(10), rootKeyCacheTtl);
    }

    @Nested
    @DisplayName("getReceipt() tests")
    class GetReceiptTests {

        @Test
        @DisplayName("Should retrieve receipt bytes")
        void shouldRetrieveReceiptBytes(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();
            byte[] expectedBytes = {0x01, 0x02, 0x03, 0x04};

            stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/receipt"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/cbor")
                    .withBody(expectedBytes)));

            TransparencyService service = createService(baseUrl);
            byte[] result = service.getReceipt(TEST_AGENT_ID);

            assertThat(result).isEqualTo(expectedBytes);
        }

        @Test
        @DisplayName("Should throw AnsNotFoundException for 404")
        void shouldThrowNotFoundFor404(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/receipt"))
                .willReturn(aResponse()
                    .withStatus(404)
                    .withHeader("X-Request-Id", "req-123")
                    .withBody("Not found")));

            TransparencyService service = createService(baseUrl);

            assertThatThrownBy(() -> service.getReceipt(TEST_AGENT_ID))
                .isInstanceOf(AnsNotFoundException.class);
        }

        @Test
        @DisplayName("Should throw AnsServerException for 500")
        void shouldThrowServerExceptionFor500(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/receipt"))
                .willReturn(aResponse()
                    .withStatus(500)
                    .withHeader("X-Request-Id", "req-456")
                    .withBody("Internal error")));

            TransparencyService service = createService(baseUrl);

            assertThatThrownBy(() -> service.getReceipt(TEST_AGENT_ID))
                .isInstanceOf(AnsServerException.class);
        }

        @Test
        @DisplayName("Should throw AnsServerException for unexpected 4xx")
        void shouldThrowServerExceptionForUnexpected4xx(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/receipt"))
                .willReturn(aResponse()
                    .withStatus(403)
                    .withBody("Forbidden")));

            TransparencyService service = createService(baseUrl);

            assertThatThrownBy(() -> service.getReceipt(TEST_AGENT_ID))
                .isInstanceOf(AnsServerException.class);
        }

        @Test
        @DisplayName("Should URL encode agent ID with special characters")
        void shouldUrlEncodeAgentId(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();
            String agentIdWithSpecialChars = "agent/with spaces";
            byte[] expectedBytes = {0x05, 0x06};

            stubFor(get(urlEqualTo("/v1/agents/agent%2Fwith+spaces/receipt"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withBody(expectedBytes)));

            TransparencyService service = createService(baseUrl);
            byte[] result = service.getReceipt(agentIdWithSpecialChars);

            assertThat(result).isEqualTo(expectedBytes);
        }
    }

    @Nested
    @DisplayName("getStatusToken() tests")
    class GetStatusTokenTests {

        @Test
        @DisplayName("Should retrieve status token bytes")
        void shouldRetrieveStatusTokenBytes(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();
            byte[] expectedBytes = {0x10, 0x20, 0x30, 0x40};

            stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/status-token"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/cose")
                    .withBody(expectedBytes)));

            TransparencyService service = createService(baseUrl);
            byte[] result = service.getStatusToken(TEST_AGENT_ID);

            assertThat(result).isEqualTo(expectedBytes);
        }

        @Test
        @DisplayName("Should throw AnsNotFoundException for 404")
        void shouldThrowNotFoundFor404(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/status-token"))
                .willReturn(aResponse()
                    .withStatus(404)
                    .withBody("Token not found")));

            TransparencyService service = createService(baseUrl);

            assertThatThrownBy(() -> service.getStatusToken(TEST_AGENT_ID))
                .isInstanceOf(AnsNotFoundException.class);
        }

        @Test
        @DisplayName("Should throw AnsServerException for 500")
        void shouldThrowServerExceptionFor500(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/status-token"))
                .willReturn(aResponse()
                    .withStatus(500)
                    .withBody("Server error")));

            TransparencyService service = createService(baseUrl);

            assertThatThrownBy(() -> service.getStatusToken(TEST_AGENT_ID))
                .isInstanceOf(AnsServerException.class);
        }
    }

    @Nested
    @DisplayName("getAgentTransparencyLog() tests")
    class GetAgentTransparencyLogTests {

        @Test
        @DisplayName("Should parse V1 payload correctly")
        void shouldParseV1Payload(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withHeader("X-Schema-Version", "V1")
                    .withBody(v1Response())));

            TransparencyService service = createService(baseUrl);
            TransparencyLog result = service.getAgentTransparencyLog(TEST_AGENT_ID);

            assertThat(result).isNotNull();
            assertThat(result.getSchemaVersion()).isEqualTo("V1");
        }

        @Test
        @DisplayName("Should parse V0 payload correctly")
        void shouldParseV0Payload(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withHeader("X-Schema-Version", "V0")
                    .withBody(v0Response())));

            TransparencyService service = createService(baseUrl);
            TransparencyLog result = service.getAgentTransparencyLog(TEST_AGENT_ID);

            assertThat(result).isNotNull();
            assertThat(result.getSchemaVersion()).isEqualTo("V0");
        }

        @Test
        @DisplayName("Should default to V0 when schema version missing")
        void shouldDefaultToV0WhenSchemaMissing(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody(v0Response())));

            TransparencyService service = createService(baseUrl);
            TransparencyLog result = service.getAgentTransparencyLog(TEST_AGENT_ID);

            assertThat(result).isNotNull();
            assertThat(result.getSchemaVersion()).isEqualTo("V0");
        }

        @Test
        @DisplayName("Should throw AnsNotFoundException for 404")
        void shouldThrowNotFoundFor404(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
                .willReturn(aResponse()
                    .withStatus(404)
                    .withHeader("X-Request-Id", "req-123")
                    .withBody("Agent not found")));

            TransparencyService service = createService(baseUrl);

            assertThatThrownBy(() -> service.getAgentTransparencyLog(TEST_AGENT_ID))
                .isInstanceOf(AnsNotFoundException.class);
        }
    }

    @Nested
    @DisplayName("getCheckpoint() tests")
    class GetCheckpointTests {

        @Test
        @DisplayName("Should retrieve checkpoint")
        void shouldRetrieveCheckpoint(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/v1/log/checkpoint"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody(checkpointResponse())));

            TransparencyService service = createService(baseUrl);
            CheckpointResponse result = service.getCheckpoint();

            assertThat(result).isNotNull();
            assertThat(result.getLogSize()).isEqualTo(1000L);
        }
    }

    @Nested
    @DisplayName("getCheckpointHistory() tests")
    class GetCheckpointHistoryTests {

        @Test
        @DisplayName("Should retrieve checkpoint history")
        void shouldRetrieveCheckpointHistory(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlMatching("/v1/log/checkpoint/history.*"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody(checkpointHistoryResponse())));

            TransparencyService service = createService(baseUrl);
            CheckpointHistoryResponse result = service.getCheckpointHistory(null);

            assertThat(result).isNotNull();
            assertThat(result.getCheckpoints()).isNotNull();
        }

        @Test
        @DisplayName("Should include query parameters")
        void shouldIncludeQueryParameters(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlMatching("/v1/log/checkpoint/history\\?.*limit=10.*"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody(checkpointHistoryResponse())));

            TransparencyService service = createService(baseUrl);
            CheckpointHistoryParams params = CheckpointHistoryParams.builder().limit(10).build();
            CheckpointHistoryResponse result = service.getCheckpointHistory(params);

            assertThat(result).isNotNull();
        }
    }

    @Nested
    @DisplayName("getLogSchema() tests")
    class GetLogSchemaTests {

        @Test
        @DisplayName("Should retrieve schema")
        void shouldRetrieveSchema(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/v1/log/schema/V1"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody("{\"type\":\"object\"}")));

            TransparencyService service = createService(baseUrl);
            Map<String, Object> result = service.getLogSchema("V1");

            assertThat(result).isNotNull();
            assertThat(result.get("type")).isEqualTo("object");
        }
    }

    @Nested
    @DisplayName("getAgentTransparencyLogAudit() tests")
    class GetAgentTransparencyLogAuditTests {

        @Test
        @DisplayName("Should retrieve audit trail")
        void shouldRetrieveAuditTrail(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlMatching("/v1/agents/" + TEST_AGENT_ID + "/audit.*"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody(auditResponse())));

            TransparencyService service = createService(baseUrl);
            TransparencyLogAudit result = service.getAgentTransparencyLogAudit(TEST_AGENT_ID, null);

            assertThat(result).isNotNull();
            assertThat(result.getRecords()).isNotNull();
        }

        @Test
        @DisplayName("Should include audit parameters")
        void shouldIncludeAuditParameters(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlMatching("/v1/agents/" + TEST_AGENT_ID + "/audit\\?.*offset=10.*"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody(auditResponse())));

            TransparencyService service = createService(baseUrl);
            AgentAuditParams params = AgentAuditParams.builder().offset(10).limit(20).build();
            TransparencyLogAudit result = service.getAgentTransparencyLogAudit(TEST_AGENT_ID, params);

            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("Should handle audit response with null records")
        void shouldHandleNullRecords(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/audit"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody("{\"totalRecords\": 0}")));

            TransparencyService service = createService(baseUrl);
            TransparencyLogAudit result = service.getAgentTransparencyLogAudit(TEST_AGENT_ID, null);

            assertThat(result).isNotNull();
            assertThat(result.getRecords()).isNull();
        }
    }

    @Nested
    @DisplayName("getRootKey() tests")
    class GetRootKeyTests {

        @Test
        @DisplayName("Should retrieve single root key from C2SP format")
        void shouldRetrieveSingleRootKeyFromC2spFormat(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/root-keys"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody(rootKeyC2spSingleResponse())));

            TransparencyService service = createService(baseUrl);
            Map<String, PublicKey> keys = service.getRootKeysAsync().join();

            assertThat(keys).hasSize(1);
            assertThat(keys.values().iterator().next().getAlgorithm()).isEqualTo("EC");
        }

        @Test
        @DisplayName("Should retrieve root key from C2SP format with alternate hash")
        void shouldRetrieveRootKeyFromC2spFormatWithAlternateHash(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/root-keys"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody(rootKeyC2spResponse())));

            TransparencyService service = createService(baseUrl);
            Map<String, PublicKey> keys = service.getRootKeysAsync().join();

            assertThat(keys).hasSize(1);
            assertThat(keys.values().iterator().next().getAlgorithm()).isEqualTo("EC");
        }

        @Test
        @DisplayName("Should retrieve root key with C2SP version byte prefix")
        void shouldRetrieveRootKeyWithC2spVersionPrefix(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            // C2SP format includes a version byte (0x02) prefix before SPKI-DER
            stubFor(get(urlEqualTo("/root-keys"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody(rootKeyC2spWithVersionByte())));

            TransparencyService service = createService(baseUrl);
            Map<String, PublicKey> keys = service.getRootKeysAsync().join();

            assertThat(keys).isNotEmpty();
            assertThat(keys.values().iterator().next().getAlgorithm()).isEqualTo("EC");
        }

        @Test
        @DisplayName("Should throw AnsServerException for 500 error")
        void shouldThrowServerExceptionFor500(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/root-keys"))
                .willReturn(aResponse()
                    .withStatus(500)
                    .withHeader("X-Request-Id", "req-123")
                    .withBody("Internal error")));

            TransparencyService service = createService(baseUrl);

            assertThatThrownBy(() -> service.getRootKeysAsync().join())
                .hasCauseInstanceOf(AnsServerException.class);
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException for invalid key format")
        void shouldThrowExceptionForInvalidFormat(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/root-keys"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody("{\"notkey\": \"value\"}")));

            TransparencyService service = createService(baseUrl);

            assertThatThrownBy(() -> service.getRootKeysAsync().join())
                .hasCauseInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Could not parse any public keys");
        }

        @Test
        @DisplayName("Should skip comment lines in C2SP format")
        void shouldSkipCommentLinesInC2spFormat(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/root-keys"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody(rootKeyC2spWithComments())));

            TransparencyService service = createService(baseUrl);
            Map<String, PublicKey> keys = service.getRootKeysAsync().join();

            assertThat(keys).isNotEmpty();
        }

        @Test
        @DisplayName("Should throw for non-200 status on root key")
        void shouldThrowForNon200Status(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/root-keys"))
                .willReturn(aResponse()
                    .withStatus(404)
                    .withHeader("X-Request-Id", "req-999")
                    .withBody("Not found")));

            TransparencyService service = createService(baseUrl);

            assertThatThrownBy(() -> service.getRootKeysAsync().join())
                .hasCauseInstanceOf(AnsServerException.class);
        }

        @Test
        @DisplayName("Should return cached root key on second call (no HTTP request)")
        void shouldReturnCachedRootKeyOnSecondCall(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/root-keys"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody(rootKeyC2spSingleResponse())));

            TransparencyService service = createService(baseUrl, Duration.ofHours(1));

            // First call - should make HTTP request
            Map<String, PublicKey> keys1 = service.getRootKeysAsync().join();
            assertThat(keys1).isNotEmpty();

            // Second call - should use cache, no HTTP request
            Map<String, PublicKey> keys2 = service.getRootKeysAsync().join();
            assertThat(keys2).isNotEmpty();
            assertThat(keys2).isSameAs(keys1);

            // Verify only one HTTP request was made
            verify(1, getRequestedFor(urlEqualTo("/root-keys")));
        }

        @Test
        @DisplayName("Should refetch root key when cache expires")
        void shouldRefetchRootKeyWhenCacheExpires(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/root-keys"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody(rootKeyC2spSingleResponse())));

            // Use very short TTL for testing
            TransparencyService service = createService(baseUrl, Duration.ofMillis(50));

            // First call - should make HTTP request
            Map<String, PublicKey> keys1 = service.getRootKeysAsync().join();
            assertThat(keys1).isNotEmpty();

            // Wait for cache to expire
            Thread.sleep(100);

            // Second call - should make another HTTP request (cache expired)
            Map<String, PublicKey> keys2 = service.getRootKeysAsync().join();
            assertThat(keys2).isNotEmpty();

            // Verify two HTTP requests were made
            verify(2, getRequestedFor(urlEqualTo("/root-keys")));
        }

        @Test
        @DisplayName("Should make only one HTTP request for concurrent calls")
        void shouldMakeOnlyOneHttpRequestForConcurrentCalls(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/root-keys"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withFixedDelay(100) // Simulate network latency
                    .withBody(rootKeyC2spSingleResponse())));

            TransparencyService service = createService(baseUrl, Duration.ofHours(1));

            int threadCount = 10;
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch doneLatch = new CountDownLatch(threadCount);
            List<Map<String, PublicKey>> results = new ArrayList<>();
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);

            try {
                // Launch concurrent requests
                for (int i = 0; i < threadCount; i++) {
                    executor.submit(() -> {
                        try {
                            startLatch.await(); // Wait for all threads to be ready
                            Map<String, PublicKey> keys = service.getRootKeysAsync().join();
                            synchronized (results) {
                                results.add(keys);
                            }
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        } finally {
                            doneLatch.countDown();
                        }
                    });
                }

                // Release all threads simultaneously
                startLatch.countDown();

                // Wait for all threads to complete
                doneLatch.await(5, TimeUnit.SECONDS);

                // All results should be the same instance
                assertThat(results).hasSize(threadCount);
                Map<String, PublicKey> firstKeys = results.get(0);
                for (Map<String, PublicKey> keys : results) {
                    assertThat(keys).isSameAs(firstKeys);
                }

                // Only one HTTP request should have been made
                verify(1, getRequestedFor(urlEqualTo("/root-keys")));
            } finally {
                executor.shutdown();
            }
        }

        @Test
        @DisplayName("Async: Should make only one HTTP request for concurrent async calls (stampede prevention)")
        void shouldMakeOnlyOneHttpRequestForConcurrentAsyncCalls(WireMockRuntimeInfo wmRuntimeInfo)
                throws InterruptedException, ExecutionException, TimeoutException {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/root-keys"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withFixedDelay(200) // Simulate network latency to ensure overlap
                    .withBody(rootKeyC2spSingleResponse())));

            TransparencyService service = createService(baseUrl, Duration.ofHours(1));

            int concurrentCalls = 10;
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch doneLatch = new CountDownLatch(concurrentCalls);
            List<CompletableFuture<Map<String, PublicKey>>> futures = new ArrayList<>();
            ExecutorService executor = Executors.newFixedThreadPool(concurrentCalls);

            try {
                // Launch concurrent async requests
                for (int i = 0; i < concurrentCalls; i++) {
                    executor.submit(() -> {
                        try {
                            startLatch.await(); // Wait for all threads to be ready
                            CompletableFuture<Map<String, PublicKey>> future = service.getRootKeysAsync();
                            synchronized (futures) {
                                futures.add(future);
                            }
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        } finally {
                            doneLatch.countDown();
                        }
                    });
                }

                // Release all threads simultaneously
                startLatch.countDown();

                // Wait for all threads to submit their futures
                doneLatch.await(5, TimeUnit.SECONDS);

                // Wait for all futures to complete and collect results
                List<Map<String, PublicKey>> results = new ArrayList<>();
                for (CompletableFuture<Map<String, PublicKey>> future : futures) {
                    results.add(future.get(5, TimeUnit.SECONDS));
                }

                // All results should be the same instance
                assertThat(results).hasSize(concurrentCalls);
                Map<String, PublicKey> firstKeys = results.get(0);
                for (Map<String, PublicKey> keys : results) {
                    assertThat(keys).isSameAs(firstKeys);
                }

                // Only one HTTP request should have been made (stampede prevention)
                verify(1, getRequestedFor(urlEqualTo("/root-keys")));
            } finally {
                executor.shutdown();
            }
        }

        @Test
        @DisplayName("Should clear cache when invalidateRootKeyCache is called")
        void shouldClearCacheWhenInvalidateCalled(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/root-keys"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody(rootKeyC2spSingleResponse())));

            TransparencyService service = createService(baseUrl, Duration.ofHours(1));

            // First call - should make HTTP request
            Map<String, PublicKey> keys1 = service.getRootKeysAsync().join();
            assertThat(keys1).isNotEmpty();
            verify(1, getRequestedFor(urlEqualTo("/root-keys")));

            // Invalidate cache
            service.invalidateRootKeyCache();

            // Second call - should make new HTTP request
            Map<String, PublicKey> keys2 = service.getRootKeysAsync().join();
            assertThat(keys2).isNotEmpty();

            // Verify two HTTP requests were made
            verify(2, getRequestedFor(urlEqualTo("/root-keys")));
        }
    }

    @Nested
    @DisplayName("refreshRootKeysIfNeeded() tests")
    class RefreshRootKeysIfNeededTests {

        @Test
        @DisplayName("Should reject artifact with future timestamp beyond tolerance")
        void shouldRejectArtifactFromFuture(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/root-keys"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody(rootKeyC2spSingleResponse())));

            TransparencyService service = createService(baseUrl);

            // Populate the cache first
            service.getRootKeysAsync().join();

            // Try refresh with artifact claiming to be 2 minutes in the future (beyond 60s tolerance)
            Instant futureTime = Instant.now().plus(Duration.ofMinutes(2));
            RefreshDecision decision = service.refreshRootKeysIfNeeded(futureTime);

            assertThat(decision.action()).isEqualTo(RefreshDecision.RefreshAction.REJECT);
            assertThat(decision.reason()).contains("future");
        }

        @Test
        @DisplayName("Should reject artifact older than cache refresh time")
        void shouldRejectArtifactOlderThanCache(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/root-keys"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody(rootKeyC2spSingleResponse())));

            TransparencyService service = createService(baseUrl);

            // Populate the cache first
            service.getRootKeysAsync().join();

            // Try refresh with artifact from 10 minutes ago (beyond 5 min past tolerance)
            Instant oldTime = Instant.now().minus(Duration.ofMinutes(10));
            RefreshDecision decision = service.refreshRootKeysIfNeeded(oldTime);

            assertThat(decision.action()).isEqualTo(RefreshDecision.RefreshAction.REJECT);
            assertThat(decision.reason()).contains("predates cache refresh");
        }

        @Test
        @DisplayName("Should allow refresh for artifact issued after cache refresh")
        void shouldAllowRefreshForNewerArtifact(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/root-keys"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody(rootKeyC2spSingleResponse())));

            TransparencyService service = createService(baseUrl);

            // Populate the cache first
            service.getRootKeysAsync().join();
            verify(1, getRequestedFor(urlEqualTo("/root-keys")));

            // Try refresh with artifact issued just now (after cache was populated)
            Instant recentTime = Instant.now();
            RefreshDecision decision = service.refreshRootKeysIfNeeded(recentTime);

            assertThat(decision.action()).isEqualTo(RefreshDecision.RefreshAction.REFRESHED);
            assertThat(decision.keys()).isNotNull();
            assertThat(decision.keys()).isNotEmpty();

            // Should have made another request to refresh the cache
            verify(2, getRequestedFor(urlEqualTo("/root-keys")));
        }

        @Test
        @DisplayName("Should defer refresh when cooldown is in effect")
        void shouldDeferRefreshDuringCooldown(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/root-keys"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody(rootKeyC2spSingleResponse())));

            TransparencyService service = createService(baseUrl);

            // Populate the cache first
            service.getRootKeysAsync().join();

            // First refresh should succeed
            Instant recentTime = Instant.now();
            RefreshDecision decision1 = service.refreshRootKeysIfNeeded(recentTime);
            assertThat(decision1.action()).isEqualTo(RefreshDecision.RefreshAction.REFRESHED);

            // Second refresh immediately after should be deferred (30s cooldown)
            RefreshDecision decision2 = service.refreshRootKeysIfNeeded(Instant.now());
            assertThat(decision2.action()).isEqualTo(RefreshDecision.RefreshAction.DEFER);
            assertThat(decision2.reason()).contains("recently refreshed");
        }

        @Test
        @DisplayName("Should track cache populated timestamp")
        void shouldTrackCachePopulatedTimestamp(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/root-keys"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody(rootKeyC2spSingleResponse())));

            TransparencyService service = createService(baseUrl);

            // Initially should be EPOCH
            assertThat(service.getCachePopulatedAt()).isEqualTo(Instant.EPOCH);

            // After populating cache, timestamp should be recent
            Instant beforeFetch = Instant.now();
            service.getRootKeysAsync().join();
            Instant afterFetch = Instant.now();

            Instant cacheTime = service.getCachePopulatedAt();
            assertThat(cacheTime).isAfterOrEqualTo(beforeFetch);
            assertThat(cacheTime).isBeforeOrEqualTo(afterFetch);
        }

        @Test
        @DisplayName("Should allow artifact within past tolerance window")
        void shouldAllowArtifactWithinPastTolerance(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/root-keys"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody(rootKeyC2spSingleResponse())));

            TransparencyService service = createService(baseUrl);

            // Populate the cache
            service.getRootKeysAsync().join();

            // Artifact from 3 minutes ago should be allowed (within 5 min past tolerance)
            Instant threeMinutesAgo = Instant.now().minus(Duration.ofMinutes(3));
            RefreshDecision decision = service.refreshRootKeysIfNeeded(threeMinutesAgo);

            // Should allow refresh since it's within tolerance
            assertThat(decision.action()).isEqualTo(RefreshDecision.RefreshAction.REFRESHED);
        }

        @Test
        @DisplayName("Should allow artifact with small future timestamp (within clock skew)")
        void shouldAllowArtifactWithinClockSkewTolerance(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            stubFor(get(urlEqualTo("/root-keys"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody(rootKeyC2spSingleResponse())));

            TransparencyService service = createService(baseUrl);

            // Populate the cache
            service.getRootKeysAsync().join();

            // Artifact from 30 seconds in future should be allowed (within 60s tolerance)
            Instant thirtySecondsAhead = Instant.now().plus(Duration.ofSeconds(30));
            RefreshDecision decision = service.refreshRootKeysIfNeeded(thirtySecondsAhead);

            // Should allow refresh since it's within clock skew tolerance
            assertThat(decision.action()).isEqualTo(RefreshDecision.RefreshAction.REFRESHED);
        }

        @Test
        @DisplayName("Should defer when network error occurs during refresh")
        void shouldDeferOnNetworkError(WireMockRuntimeInfo wmRuntimeInfo) {
            String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

            // First request succeeds (initial cache population)
            stubFor(get(urlEqualTo("/root-keys"))
                .inScenario("network-error")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/plain")
                    .withBody(rootKeyC2spSingleResponse()))
                .willSetStateTo("first-call-done"));

            // Second request fails (network error during refresh)
            stubFor(get(urlEqualTo("/root-keys"))
                .inScenario("network-error")
                .whenScenarioStateIs("first-call-done")
                .willReturn(aResponse()
                    .withStatus(500)
                    .withBody("Server error")));

            TransparencyService service = createService(baseUrl);

            // Populate the cache
            service.getRootKeysAsync().join();

            // Attempt refresh - should fail and return DEFER
            Instant recentTime = Instant.now();
            RefreshDecision decision = service.refreshRootKeysIfNeeded(recentTime);

            assertThat(decision.action()).isEqualTo(RefreshDecision.RefreshAction.DEFER);
            assertThat(decision.reason()).contains("Failed to refresh");
        }
    }

    // Helper methods for test data

    private String v1Response() {
        return """
            {
              "status": "ACTIVE",
              "schemaVersion": "V1",
              "payload": {
                "logId": "log-123",
                "producer": {
                  "event": {
                    "ansId": "6bf2b7a9-1383-4e33-a945-845f34af7526",
                    "ansName": "ans://v1.0.0.agent.example.com",
                    "eventType": "AGENT_REGISTERED",
                    "agent": {
                      "host": "agent.example.com",
                      "name": "Example Agent",
                      "version": "v1.0.0"
                    },
                    "attestations": {
                      "domainValidation": "ACME-DNS-01"
                    }
                  }
                }
              }
            }
            """;
    }

    private String v0Response() {
        return """
            {
              "status": "ACTIVE",
              "schemaVersion": "V0",
              "payload": {
                "ansId": "6bf2b7a9-1383-4e33-a945-845f34af7526",
                "ansName": "ans://v1.0.0.agent.example.com",
                "eventType": "AGENT_REGISTERED"
              }
            }
            """;
    }

    private String checkpointResponse() {
        return """
            {
              "logSize": 1000,
              "rootHash": "abcd1234"
            }
            """;
    }

    private String checkpointHistoryResponse() {
        return """
            {
              "checkpoints": [
                {
                  "logSize": 1000,
                  "rootHash": "abcd1234"
                }
              ]
            }
            """;
    }

    private String auditResponse() {
        return """
            {
              "records": [],
              "totalRecords": 5
            }
            """;
    }

    // Valid EC P-256 public key for testing (SPKI-DER, base64 encoded)
    private static final String TEST_EC_PUBLIC_KEY =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEveuRZW0vWcVjh4enr9tA7VAKPFmL"
        + "OZs1S99lGDqRhAQBEdetB290Det8rO1ojnHEA8PX4Yojb0oomwA2krO5Ag==";

    /**
     * Returns a valid EC P-256 public key in JSON format.
     */
    private String rootKeyC2spSingleResponse() {
        return "transparency.ans.godaddy.com+abcd1234+" + TEST_EC_PUBLIC_KEY;
    }

    /**
     * Returns a valid EC P-256 public key in C2SP note format.
     */
    private String rootKeyC2spResponse() {
        return "transparency.ans.godaddy.com+abc123+" + TEST_EC_PUBLIC_KEY;
    }

    /**
     * Returns a valid EC P-256 public key with C2SP version byte prefix (0x02).
     * This tests the version byte stripping logic in decodePublicKey().
     */
    private String rootKeyC2spWithVersionByte() {
        // Prepend 0x02 version byte to the SPKI-DER bytes
        byte[] originalKey = java.util.Base64.getDecoder().decode(TEST_EC_PUBLIC_KEY);
        byte[] prefixedKey = new byte[originalKey.length + 1];
        prefixedKey[0] = 0x02; // C2SP version byte
        System.arraycopy(originalKey, 0, prefixedKey, 1, originalKey.length);
        String prefixedBase64 = java.util.Base64.getEncoder().encodeToString(prefixedKey);
        return "transparency.ans.godaddy.com+abc123+" + prefixedBase64;
    }

    /**
     * Returns a C2SP note format with comment lines.
     */
    private String rootKeyC2spWithComments() {
        return "# This is a comment\n\n"
            + "transparency.ans.godaddy.com+abc123+" + TEST_EC_PUBLIC_KEY;
    }
}