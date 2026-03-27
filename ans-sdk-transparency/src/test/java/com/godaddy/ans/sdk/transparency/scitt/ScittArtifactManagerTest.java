package com.godaddy.ans.sdk.transparency.scitt;

import com.godaddy.ans.sdk.transparency.TransparencyClient;
import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ScittArtifactManagerTest {

    private TransparencyClient mockClient;
    private ScittArtifactManager manager;

    @BeforeEach
    void setUp() {
        mockClient = mock(TransparencyClient.class);
    }

    @AfterEach
    void tearDown() {
        if (manager != null) {
            manager.close();
        }
    }

    @Nested
    @DisplayName("Builder tests")
    class BuilderTests {

        @Test
        @DisplayName("Should require transparency client")
        void shouldRequireTransparencyClient() {
            assertThatThrownBy(() -> ScittArtifactManager.builder().build())
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("transparencyClient cannot be null");
        }

        @Test
        @DisplayName("Should build with minimum configuration")
        void shouldBuildWithMinimumConfiguration() {
            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            assertThat(manager).isNotNull();
        }

        @Test
        @DisplayName("Should build with custom scheduler")
        void shouldBuildWithCustomScheduler() {
            ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
            try {
                manager = ScittArtifactManager.builder()
                    .transparencyClient(mockClient)
                    .scheduler(scheduler)
                    .build();

                assertThat(manager).isNotNull();
            } finally {
                scheduler.shutdown();
            }
        }

    }

    @Nested
    @DisplayName("getReceipt() tests")
    class GetReceiptTests {

        @Test
        @DisplayName("Should reject null agentId")
        void shouldRejectNullAgentId() {
            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            assertThatThrownBy(() -> manager.getReceipt(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("agentId cannot be null");
        }

        @Test
        @DisplayName("Should return failed future when manager is closed")
        void shouldReturnFailedFutureWhenClosed() {
            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            manager.close();

            CompletableFuture<ScittReceipt> future = manager.getReceipt("test-agent");
            assertThat(future).isCompletedExceptionally();
        }

        @Test
        @DisplayName("Should fetch receipt from transparency client")
        void shouldFetchReceiptFromClient() throws Exception {
            byte[] receiptBytes = createValidReceiptBytes();
            when(mockClient.getReceipt("test-agent")).thenReturn(receiptBytes);

            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            CompletableFuture<ScittReceipt> future = manager.getReceipt("test-agent");
            ScittReceipt receipt = future.get(5, TimeUnit.SECONDS);

            assertThat(receipt).isNotNull();
            verify(mockClient).getReceipt("test-agent");
        }

        @Test
        @DisplayName("Should cache receipt on subsequent calls")
        void shouldCacheReceipt() throws Exception {
            byte[] receiptBytes = createValidReceiptBytes();
            when(mockClient.getReceipt("test-agent")).thenReturn(receiptBytes);

            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            // First call
            manager.getReceipt("test-agent").get(5, TimeUnit.SECONDS);
            // Second call should use cache
            manager.getReceipt("test-agent").get(5, TimeUnit.SECONDS);

            // Client should only be called once
            verify(mockClient, times(1)).getReceipt("test-agent");
        }

        @Test
        @DisplayName("Should wrap client exception in ScittFetchException")
        void shouldWrapClientException() {
            when(mockClient.getReceipt(anyString())).thenThrow(new RuntimeException("Network error"));

            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            CompletableFuture<ScittReceipt> future = manager.getReceipt("test-agent");

            assertThatThrownBy(() -> future.get(5, TimeUnit.SECONDS))
                .hasCauseInstanceOf(ScittFetchException.class)
                .hasMessageContaining("Failed to fetch receipt");
        }
    }

    @Nested
    @DisplayName("getStatusToken() tests")
    class GetStatusTokenTests {

        @Test
        @DisplayName("Should reject null agentId")
        void shouldRejectNullAgentId() {
            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            assertThatThrownBy(() -> manager.getStatusToken(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("agentId cannot be null");
        }

        @Test
        @DisplayName("Should return failed future when manager is closed")
        void shouldReturnFailedFutureWhenClosed() {
            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            manager.close();

            CompletableFuture<StatusToken> future = manager.getStatusToken("test-agent");
            assertThat(future).isCompletedExceptionally();
        }

        @Test
        @DisplayName("Should fetch status token from transparency client")
        void shouldFetchTokenFromClient() throws Exception {
            byte[] tokenBytes = createValidStatusTokenBytes();
            when(mockClient.getStatusToken("test-agent")).thenReturn(tokenBytes);

            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            CompletableFuture<StatusToken> future = manager.getStatusToken("test-agent");
            StatusToken token = future.get(5, TimeUnit.SECONDS);

            assertThat(token).isNotNull();
            verify(mockClient).getStatusToken("test-agent");
        }

        @Test
        @DisplayName("Should cache status token on subsequent calls")
        void shouldCacheToken() throws Exception {
            byte[] tokenBytes = createValidStatusTokenBytes();
            when(mockClient.getStatusToken("test-agent")).thenReturn(tokenBytes);

            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            // First call
            manager.getStatusToken("test-agent").get(5, TimeUnit.SECONDS);
            // Second call should use cache
            manager.getStatusToken("test-agent").get(5, TimeUnit.SECONDS);

            verify(mockClient, times(1)).getStatusToken("test-agent");
        }

        @Test
        @DisplayName("Should wrap client exception in ScittFetchException")
        void shouldWrapClientException() {
            when(mockClient.getStatusToken(anyString())).thenThrow(new RuntimeException("Network error"));

            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            CompletableFuture<StatusToken> future = manager.getStatusToken("test-agent");

            assertThatThrownBy(() -> future.get(5, TimeUnit.SECONDS))
                .hasCauseInstanceOf(ScittFetchException.class)
                .hasMessageContaining("Failed to fetch status token");
        }

        @Test
        @DisplayName("Should coalesce concurrent status token requests")
        void shouldCoalesceConcurrentRequests() throws Exception {
            // Delay the response to simulate slow network
            byte[] tokenBytes = createValidStatusTokenBytes();
            when(mockClient.getStatusToken("test-agent")).thenAnswer(invocation -> {
                Thread.sleep(200); // Simulate network delay
                return tokenBytes;
            });

            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            // Start two concurrent requests
            CompletableFuture<StatusToken> future1 = manager.getStatusToken("test-agent");
            CompletableFuture<StatusToken> future2 = manager.getStatusToken("test-agent");

            // Both should complete
            StatusToken token1 = future1.get(5, TimeUnit.SECONDS);
            StatusToken token2 = future2.get(5, TimeUnit.SECONDS);

            // Both should get the same token
            assertThat(token1).isNotNull();
            assertThat(token2).isNotNull();

            // Client should only be called once due to pending request coalescing
            // (or twice if the second request started after first completed)
            verify(mockClient, times(1)).getStatusToken("test-agent");
        }
    }

    @Nested
    @DisplayName("getReceiptBase64() tests")
    class GetReceiptBytesTests {

        @Test
        @DisplayName("Should reject null agentId")
        void shouldRejectNullAgentId() {
            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            assertThatThrownBy(() -> manager.getReceiptBase64(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("agentId cannot be null");
        }

        @Test
        @DisplayName("Should return failed future when manager is closed")
        void shouldReturnFailedFutureWhenClosed() {
            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            manager.close();

            CompletableFuture<String> future = manager.getReceiptBase64("test-agent");
            assertThat(future).isCompletedExceptionally();
        }

        @Test
        @DisplayName("Should fetch receipt Base64 from transparency client")
        void shouldFetchReceiptBase64FromClient() throws Exception {
            byte[] receiptBytes = createValidReceiptBytes();
            when(mockClient.getReceipt("test-agent")).thenReturn(receiptBytes);

            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            CompletableFuture<String> future = manager.getReceiptBase64("test-agent");
            String result = future.get(5, TimeUnit.SECONDS);

            assertThat(result).isNotNull();
            assertThat(result).isNotEmpty();
            // Verify it's valid Base64 that decodes to the original bytes
            assertThat(java.util.Base64.getDecoder().decode(result)).isEqualTo(receiptBytes);
            verify(mockClient).getReceipt("test-agent");
        }

        @Test
        @DisplayName("Should cache receipt Base64 on subsequent calls")
        void shouldCacheReceiptBase64() throws Exception {
            byte[] receiptBytes = createValidReceiptBytes();
            when(mockClient.getReceipt("test-agent")).thenReturn(receiptBytes);

            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            // First call
            String first = manager.getReceiptBase64("test-agent").get(5, TimeUnit.SECONDS);
            // Second call should use cache and return same String instance
            String second = manager.getReceiptBase64("test-agent").get(5, TimeUnit.SECONDS);

            assertThat(first).isSameAs(second);
            // Client should only be called once
            verify(mockClient, times(1)).getReceipt("test-agent");
        }

        @Test
        @DisplayName("Should wrap client exception in ScittFetchException")
        void shouldWrapClientException() {
            when(mockClient.getReceipt(anyString())).thenThrow(new RuntimeException("Network error"));

            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            CompletableFuture<String> future = manager.getReceiptBase64("test-agent");

            assertThatThrownBy(() -> future.get(5, TimeUnit.SECONDS))
                .hasCauseInstanceOf(ScittFetchException.class)
                .hasMessageContaining("Failed to fetch receipt");
        }
    }

    @Nested
    @DisplayName("getStatusTokenBase64() tests")
    class GetStatusTokenBytesTests {

        @Test
        @DisplayName("Should reject null agentId")
        void shouldRejectNullAgentId() {
            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            assertThatThrownBy(() -> manager.getStatusTokenBase64(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("agentId cannot be null");
        }

        @Test
        @DisplayName("Should return failed future when manager is closed")
        void shouldReturnFailedFutureWhenClosed() {
            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            manager.close();

            CompletableFuture<String> future = manager.getStatusTokenBase64("test-agent");
            assertThat(future).isCompletedExceptionally();
        }

        @Test
        @DisplayName("Should fetch status token Base64 from transparency client")
        void shouldFetchTokenBase64FromClient() throws Exception {
            byte[] tokenBytes = createValidStatusTokenBytes();
            when(mockClient.getStatusToken("test-agent")).thenReturn(tokenBytes);

            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            CompletableFuture<String> future = manager.getStatusTokenBase64("test-agent");
            String result = future.get(5, TimeUnit.SECONDS);

            assertThat(result).isNotNull();
            assertThat(result).isNotEmpty();
            // Verify it's valid Base64 that decodes to the original bytes
            assertThat(java.util.Base64.getDecoder().decode(result)).isEqualTo(tokenBytes);
            verify(mockClient).getStatusToken("test-agent");
        }

        @Test
        @DisplayName("Should cache status token Base64 on subsequent calls")
        void shouldCacheTokenBase64() throws Exception {
            byte[] tokenBytes = createValidStatusTokenBytes();
            when(mockClient.getStatusToken("test-agent")).thenReturn(tokenBytes);

            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            // First call
            String first = manager.getStatusTokenBase64("test-agent").get(5, TimeUnit.SECONDS);
            // Second call should use cache and return same String instance
            String second = manager.getStatusTokenBase64("test-agent").get(5, TimeUnit.SECONDS);

            assertThat(first).isSameAs(second);
            verify(mockClient, times(1)).getStatusToken("test-agent");
        }

        @Test
        @DisplayName("Should wrap client exception in ScittFetchException")
        void shouldWrapClientException() {
            when(mockClient.getStatusToken(anyString())).thenThrow(new RuntimeException("Network error"));

            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            CompletableFuture<String> future = manager.getStatusTokenBase64("test-agent");

            assertThatThrownBy(() -> future.get(5, TimeUnit.SECONDS))
                .hasCauseInstanceOf(ScittFetchException.class)
                .hasMessageContaining("Failed to fetch status token");
        }
    }

    @Nested
    @DisplayName("Background refresh tests")
    class BackgroundRefreshTests {

        @Test
        @DisplayName("Should not start refresh when manager is closed")
        void shouldNotStartWhenClosed() {
            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            manager.close();

            // Should not throw
            manager.startBackgroundRefresh("test-agent");
        }

        @Test
        @DisplayName("Should stop background refresh")
        void shouldStopBackgroundRefresh() throws Exception {
            byte[] tokenBytes = createValidStatusTokenBytes();
            when(mockClient.getStatusToken("test-agent")).thenReturn(tokenBytes);

            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            // Fetch initial token
            manager.getStatusToken("test-agent").get(5, TimeUnit.SECONDS);

            // Start refresh
            manager.startBackgroundRefresh("test-agent");

            // Stop refresh
            manager.stopBackgroundRefresh("test-agent");

            // Should not throw
        }

        @Test
        @DisplayName("Should handle stopping non-existent refresh")
        void shouldHandleStoppingNonExistentRefresh() {
            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            // Should not throw
            manager.stopBackgroundRefresh("non-existent-agent");
        }

        @Test
        @DisplayName("Should start refresh without cached token using default interval")
        void shouldStartRefreshWithoutCachedToken() throws Exception {
            byte[] tokenBytes = createValidStatusTokenBytes();
            when(mockClient.getStatusToken("test-agent")).thenReturn(tokenBytes);

            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            // Start refresh without fetching token first
            manager.startBackgroundRefresh("test-agent");

            // Should not throw - uses default 5 minute interval
            Thread.sleep(100); // Give scheduler time to initialize

            manager.stopBackgroundRefresh("test-agent");
        }

        @Test
        @DisplayName("Should replace existing refresh task when starting again")
        void shouldReplaceExistingRefreshTask() throws Exception {
            byte[] tokenBytes = createValidStatusTokenBytes();
            when(mockClient.getStatusToken("test-agent")).thenReturn(tokenBytes);

            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            // Fetch token
            manager.getStatusToken("test-agent").get(5, TimeUnit.SECONDS);

            // Start refresh twice
            manager.startBackgroundRefresh("test-agent");
            manager.startBackgroundRefresh("test-agent");

            // Should not throw, second call should replace first
            manager.stopBackgroundRefresh("test-agent");
        }
    }

    @Nested
    @DisplayName("Cache management tests")
    class CacheManagementTests {

        @Test
        @DisplayName("Should clear cache for specific agent")
        void shouldClearCacheForAgent() throws Exception {
            byte[] receiptBytes = createValidReceiptBytes();
            byte[] tokenBytes = createValidStatusTokenBytes();
            when(mockClient.getReceipt("test-agent")).thenReturn(receiptBytes);
            when(mockClient.getStatusToken("test-agent")).thenReturn(tokenBytes);

            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            // Populate cache
            manager.getReceipt("test-agent").get(5, TimeUnit.SECONDS);
            manager.getStatusToken("test-agent").get(5, TimeUnit.SECONDS);

            // Clear cache
            manager.clearCache("test-agent");

            // Fetch again - should hit client
            manager.getReceipt("test-agent").get(5, TimeUnit.SECONDS);

            verify(mockClient, times(2)).getReceipt("test-agent");
        }

        @Test
        @DisplayName("Should clear all caches")
        void shouldClearAllCaches() throws Exception {
            byte[] receiptBytes = createValidReceiptBytes();
            byte[] tokenBytes = createValidStatusTokenBytes();
            when(mockClient.getReceipt(anyString())).thenReturn(receiptBytes);
            when(mockClient.getStatusToken(anyString())).thenReturn(tokenBytes);

            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            // Populate caches for multiple agents
            manager.getReceipt("agent1").get(5, TimeUnit.SECONDS);
            manager.getReceipt("agent2").get(5, TimeUnit.SECONDS);

            // Clear all
            manager.clearAllCaches();

            // Fetch again - should hit client
            manager.getReceipt("agent1").get(5, TimeUnit.SECONDS);
            manager.getReceipt("agent2").get(5, TimeUnit.SECONDS);

            verify(mockClient, times(2)).getReceipt("agent1");
            verify(mockClient, times(2)).getReceipt("agent2");
        }
    }

    @Nested
    @DisplayName("AutoCloseable tests")
    class AutoCloseableTests {

        @Test
        @DisplayName("Should shutdown scheduler on close")
        void shouldShutdownSchedulerOnClose() {
            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            manager.close();

            // Verify manager is closed by checking subsequent operations fail
            assertThat(manager.getReceipt("test")).isCompletedExceptionally();
        }

        @Test
        @DisplayName("Should be idempotent when closing multiple times")
        void shouldBeIdempotentOnClose() {
            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            manager.close();
            manager.close();
            manager.close();

            // Should not throw
        }

        @Test
        @DisplayName("Should cancel refresh tasks on close")
        void shouldCancelRefreshTasksOnClose() throws Exception {
            byte[] tokenBytes = createValidStatusTokenBytes();
            when(mockClient.getStatusToken("test-agent")).thenReturn(tokenBytes);

            manager = ScittArtifactManager.builder()
                .transparencyClient(mockClient)
                .build();

            manager.getStatusToken("test-agent").get(5, TimeUnit.SECONDS);
            manager.startBackgroundRefresh("test-agent");

            manager.close();

            // Should not throw
        }

        @Test
        @DisplayName("Should not shutdown external scheduler")
        void shouldNotShutdownExternalScheduler() throws Exception {
            ScheduledExecutorService externalScheduler = Executors.newSingleThreadScheduledExecutor();

            try {
                manager = ScittArtifactManager.builder()
                    .transparencyClient(mockClient)
                    .scheduler(externalScheduler)
                    .build();

                manager.close();

                // External scheduler should still be running
                assertThat(externalScheduler.isShutdown()).isFalse();
            } finally {
                externalScheduler.shutdown();
            }
        }
    }

    // Helper methods

    private byte[] createValidReceiptBytes() {
        // Create a minimal valid COSE_Sign1 for receipt
        CBORObject protectedHeader = CBORObject.NewMap();
        protectedHeader.Add(1, -7);  // alg = ES256
        protectedHeader.Add(395, 1);  // vds = RFC9162_SHA256 (required for receipts)
        byte[] protectedBytes = protectedHeader.EncodeToBytes();

        byte[] payload = "test-payload".getBytes();
        byte[] signature = new byte[64];

        // Create unprotected header with inclusion proof (MAP format)
        CBORObject inclusionProofMap = CBORObject.NewMap();
        inclusionProofMap.Add(-1, 1L);  // tree_size
        inclusionProofMap.Add(-2, 0L);  // leaf_index
        inclusionProofMap.Add(-3, CBORObject.NewArray());  // empty hash_path
        inclusionProofMap.Add(-4, CBORObject.FromObject(new byte[32]));  // root_hash

        CBORObject unprotectedHeader = CBORObject.NewMap();
        unprotectedHeader.Add(396, inclusionProofMap);  // proofs label

        CBORObject array = CBORObject.NewArray();
        array.Add(protectedBytes);
        array.Add(unprotectedHeader);
        array.Add(payload);
        array.Add(signature);
        CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

        return tagged.EncodeToBytes();
    }

    private byte[] createReceiptPayload() {
        return "test-payload".getBytes();
    }

    private byte[] createValidStatusTokenBytes() {
        // Create a minimal valid COSE_Sign1 for status token
        CBORObject protectedHeader = CBORObject.NewMap();
        protectedHeader.Add(1, -7);  // alg = ES256
        byte[] protectedBytes = protectedHeader.EncodeToBytes();

        byte[] payload = createStatusTokenPayload();
        byte[] signature = new byte[64];

        CBORObject array = CBORObject.NewArray();
        array.Add(protectedBytes);
        array.Add(CBORObject.NewMap());
        array.Add(payload);
        array.Add(signature);
        CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

        return tagged.EncodeToBytes();
    }

    private byte[] createStatusTokenPayload() {
        // Use integer keys: 1=agent_id, 2=status, 3=iat, 4=exp
        CBORObject payload = CBORObject.NewMap();
        payload.Add(1, "test-agent");  // agent_id
        payload.Add(2, "ACTIVE");      // status
        payload.Add(3, Instant.now().minusSeconds(60).getEpochSecond());  // iat
        payload.Add(4, Instant.now().plusSeconds(3600).getEpochSecond()); // exp
        return payload.EncodeToBytes();
    }
}
