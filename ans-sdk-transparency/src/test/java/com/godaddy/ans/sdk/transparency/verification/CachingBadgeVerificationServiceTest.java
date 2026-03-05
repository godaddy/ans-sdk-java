package com.godaddy.ans.sdk.transparency.verification;

import com.godaddy.ans.sdk.transparency.model.AgentV1;
import com.godaddy.ans.sdk.transparency.model.AttestationsV1;
import com.godaddy.ans.sdk.transparency.model.CertificateInfo;
import com.godaddy.ans.sdk.transparency.model.CertType;
import com.godaddy.ans.sdk.transparency.model.EventV1;
import com.godaddy.ans.sdk.transparency.model.ProducerV1;
import com.godaddy.ans.sdk.transparency.model.TransparencyLog;
import com.godaddy.ans.sdk.transparency.model.TransparencyLogV1;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.security.cert.X509Certificate;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link CachingBadgeVerificationService}.
 */
class CachingBadgeVerificationServiceTest {

    private static final String TEST_HOSTNAME = "agent.example.com";
    private static final String TEST_FINGERPRINT = "SHA256:a1b2c3d4e5f6g7h8";
    private static final String TEST_ANS_NAME = "ans://v1.0.0.agent.example.com";

    @Mock
    private BadgeVerificationService delegate;

    @Mock
    private X509Certificate mockCertificate;

    private CachingBadgeVerificationService cachingService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    // ==================== Cache Hit Within TTL ====================

    @Test
    @DisplayName("Should return cached result within TTL for server verification")
    void shouldReturnCachedResultWithinTtlForServerVerification() {
        // Given
        cachingService = CachingBadgeVerificationService.builder()
            .delegate(delegate)
            .cacheTtl(Duration.ofMinutes(15))
            .build();

        ServerVerificationResult expectedResult = createSuccessfulServerResult();
        when(delegate.verifyServer(TEST_HOSTNAME)).thenReturn(expectedResult);

        // When - first call
        ServerVerificationResult firstResult = cachingService.verifyServer(TEST_HOSTNAME);

        // Then - delegate called once
        assertThat(firstResult.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        verify(delegate, times(1)).verifyServer(TEST_HOSTNAME);

        // When - second call within TTL
        ServerVerificationResult secondResult = cachingService.verifyServer(TEST_HOSTNAME);

        // Then - delegate NOT called again (cache hit)
        assertThat(secondResult.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        assertThat(secondResult).isSameAs(firstResult);
        verify(delegate, times(1)).verifyServer(TEST_HOSTNAME); // Still only 1 call
    }

    @Test
    @DisplayName("Should return cached result within TTL for client verification")
    void shouldReturnCachedResultWithinTtlForClientVerification() throws Exception {
        // Given
        cachingService = CachingBadgeVerificationService.builder()
            .delegate(delegate)
            .cacheTtl(Duration.ofMinutes(15))
            .build();

        // Mock certificate encoding for fingerprint computation
        byte[] certBytes = "test-cert-bytes".getBytes();
        when(mockCertificate.getEncoded()).thenReturn(certBytes);

        ClientVerificationResult expectedResult = createSuccessfulClientResult();
        when(delegate.verifyClient(mockCertificate)).thenReturn(expectedResult);

        // When - first call
        ClientVerificationResult firstResult = cachingService.verifyClient(mockCertificate);

        // Then - delegate called once
        assertThat(firstResult.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        verify(delegate, times(1)).verifyClient(mockCertificate);

        // When - second call within TTL
        ClientVerificationResult secondResult = cachingService.verifyClient(mockCertificate);

        // Then - delegate NOT called again (cache hit)
        assertThat(secondResult.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        assertThat(secondResult).isSameAs(firstResult);
        verify(delegate, times(1)).verifyClient(mockCertificate); // Still only 1 call
    }

    // ==================== Cache Stale, TL Available ====================

    @Test
    @DisplayName("Should refresh badge when cache is stale and TL available")
    void shouldRefreshBadgeWhenCacheStaleAndTlAvailable() throws InterruptedException {
        // Given - very short TTL for testing
        cachingService = CachingBadgeVerificationService.builder()
            .delegate(delegate)
            .cacheTtl(Duration.ofMillis(50))
            .build();

        ServerVerificationResult firstExpectedResult = createSuccessfulServerResult();
        ServerVerificationResult secondExpectedResult = createSuccessfulServerResult();
        when(delegate.verifyServer(TEST_HOSTNAME))
            .thenReturn(firstExpectedResult)
            .thenReturn(secondExpectedResult);

        // When - first call
        ServerVerificationResult firstResult = cachingService.verifyServer(TEST_HOSTNAME);
        assertThat(firstResult).isSameAs(firstExpectedResult);
        verify(delegate, times(1)).verifyServer(TEST_HOSTNAME);

        // Wait for cache to expire
        Thread.sleep(100);

        // When - second call after TTL expired
        ServerVerificationResult secondResult = cachingService.verifyServer(TEST_HOSTNAME);

        // Then - delegate called again (cache miss)
        assertThat(secondResult).isSameAs(secondExpectedResult);
        verify(delegate, times(2)).verifyServer(TEST_HOSTNAME);
    }

    // ==================== Cache Stale, TL Unreachable ====================

    @Test
    @DisplayName("Should return failure when cache stale and TL unreachable")
    void shouldReturnFailureWhenCacheStaleAndTlUnreachable() throws InterruptedException {
        // Given - very short TTL for testing
        cachingService = CachingBadgeVerificationService.builder()
            .delegate(delegate)
            .cacheTtl(Duration.ofMillis(50))
            .negativeCacheTtl(Duration.ofMillis(50))
            .build();

        ServerVerificationResult successResult = createSuccessfulServerResult();
        ServerVerificationResult failureResult = createFailedServerResult();

        when(delegate.verifyServer(TEST_HOSTNAME))
            .thenReturn(successResult)
            .thenReturn(failureResult);

        // When - first call succeeds
        ServerVerificationResult firstResult = cachingService.verifyServer(TEST_HOSTNAME);
        assertThat(firstResult.getStatus()).isEqualTo(VerificationStatus.VERIFIED);

        // Wait for cache to expire
        Thread.sleep(100);

        // When - second call fails (TL unreachable)
        ServerVerificationResult secondResult = cachingService.verifyServer(TEST_HOSTNAME);

        // Then - returns failure result
        assertThat(secondResult.getStatus()).isEqualTo(VerificationStatus.LOOKUP_FAILED);
        verify(delegate, times(2)).verifyServer(TEST_HOSTNAME);
    }

    @Test
    @DisplayName("Should cache negative results with shorter TTL")
    void shouldCacheNegativeResultsWithShorterTtl() {
        // Given - different TTLs for positive and negative results
        cachingService = CachingBadgeVerificationService.builder()
            .delegate(delegate)
            .cacheTtl(Duration.ofMinutes(15))
            .negativeCacheTtl(Duration.ofMinutes(5))
            .build();

        ServerVerificationResult failureResult = createFailedServerResult();
        when(delegate.verifyServer(TEST_HOSTNAME)).thenReturn(failureResult);

        // When - first call
        ServerVerificationResult firstResult = cachingService.verifyServer(TEST_HOSTNAME);

        // Then
        assertThat(firstResult.getStatus()).isEqualTo(VerificationStatus.LOOKUP_FAILED);
        verify(delegate, times(1)).verifyServer(TEST_HOSTNAME);

        // When - second call (should still be cached)
        ServerVerificationResult secondResult = cachingService.verifyServer(TEST_HOSTNAME);

        // Then - cached negative result returned
        assertThat(secondResult.getStatus()).isEqualTo(VerificationStatus.LOOKUP_FAILED);
        verify(delegate, times(1)).verifyServer(TEST_HOSTNAME); // Still only 1 call
    }

    // ==================== Background Refresh / Cache Management ====================

    @Test
    @DisplayName("Should evict expired entries when evictExpired is called")
    void shouldEvictExpiredEntriesWhenEvictExpiredCalled() throws InterruptedException {
        // Given - very short TTL
        cachingService = CachingBadgeVerificationService.builder()
            .delegate(delegate)
            .cacheTtl(Duration.ofMillis(50))
            .build();

        ServerVerificationResult result = createSuccessfulServerResult();
        when(delegate.verifyServer(TEST_HOSTNAME)).thenReturn(result);

        // Populate cache
        cachingService.verifyServer(TEST_HOSTNAME);
        assertThat(cachingService.serverCacheSize()).isEqualTo(1);

        // Wait for expiry
        Thread.sleep(100);

        // When - evict expired entries
        cachingService.evictExpired();

        // Then - cache is empty
        assertThat(cachingService.serverCacheSize()).isEqualTo(0);
    }

    @Test
    @DisplayName("Should not evict non-expired entries when evictExpired is called")
    void shouldNotEvictNonExpiredEntriesWhenEvictExpiredCalled() {
        // Given - long TTL
        cachingService = CachingBadgeVerificationService.builder()
            .delegate(delegate)
            .cacheTtl(Duration.ofMinutes(15))
            .build();

        ServerVerificationResult result = createSuccessfulServerResult();
        when(delegate.verifyServer(TEST_HOSTNAME)).thenReturn(result);

        // Populate cache
        cachingService.verifyServer(TEST_HOSTNAME);
        assertThat(cachingService.serverCacheSize()).isEqualTo(1);

        // When - evict expired entries (none should be expired)
        cachingService.evictExpired();

        // Then - cache still has entry
        assertThat(cachingService.serverCacheSize()).isEqualTo(1);
    }

    // ==================== Cache Invalidation ====================

    @Test
    @DisplayName("Should invalidate specific server from cache")
    void shouldInvalidateSpecificServerFromCache() {
        // Given
        cachingService = CachingBadgeVerificationService.builder()
            .delegate(delegate)
            .cacheTtl(Duration.ofMinutes(15))
            .build();

        ServerVerificationResult result = createSuccessfulServerResult();
        when(delegate.verifyServer(anyString())).thenReturn(result);

        // Populate cache with multiple entries
        cachingService.verifyServer("agent1.example.com");
        cachingService.verifyServer("agent2.example.com");
        assertThat(cachingService.serverCacheSize()).isEqualTo(2);

        // When - invalidate one entry
        cachingService.invalidateServer("agent1.example.com");

        // Then - only one entry remains
        assertThat(cachingService.serverCacheSize()).isEqualTo(1);

        // And - the invalidated entry is re-fetched on next call
        cachingService.verifyServer("agent1.example.com");
        verify(delegate, times(2)).verifyServer("agent1.example.com");
    }

    @Test
    @DisplayName("Should clear all cached entries")
    void shouldClearAllCachedEntries() throws Exception {
        // Given
        cachingService = CachingBadgeVerificationService.builder()
            .delegate(delegate)
            .cacheTtl(Duration.ofMinutes(15))
            .build();

        ServerVerificationResult serverResult = createSuccessfulServerResult();
        ClientVerificationResult clientResult = createSuccessfulClientResult();
        when(delegate.verifyServer(anyString())).thenReturn(serverResult);
        when(delegate.verifyClient(any())).thenReturn(clientResult);

        byte[] certBytes = "test-cert-bytes".getBytes();
        when(mockCertificate.getEncoded()).thenReturn(certBytes);

        // Populate caches
        cachingService.verifyServer(TEST_HOSTNAME);
        cachingService.verifyClient(mockCertificate);
        assertThat(cachingService.serverCacheSize()).isEqualTo(1);
        assertThat(cachingService.clientCacheSize()).isEqualTo(1);

        // When - clear all
        cachingService.clearCache();

        // Then - both caches empty
        assertThat(cachingService.serverCacheSize()).isEqualTo(0);
        assertThat(cachingService.clientCacheSize()).isEqualTo(0);
    }

    // ==================== Builder Validation ====================

    @Test
    @DisplayName("Should throw exception when delegate is null")
    void shouldThrowExceptionWhenDelegateIsNull() {
        // When/Then
        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class, () -> {
            CachingBadgeVerificationService.builder()
                .cacheTtl(Duration.ofMinutes(15))
                .build();
        });
    }

    @Test
    @DisplayName("Should use default TTLs when not specified")
    void shouldUseDefaultTtlsWhenNotSpecified() {
        // Given
        cachingService = CachingBadgeVerificationService.builder()
            .delegate(delegate)
            .build();

        ServerVerificationResult result = createSuccessfulServerResult();
        when(delegate.verifyServer(TEST_HOSTNAME)).thenReturn(result);

        // When - call twice
        cachingService.verifyServer(TEST_HOSTNAME);
        cachingService.verifyServer(TEST_HOSTNAME);

        // Then - delegate called only once (default TTL should be long enough)
        verify(delegate, times(1)).verifyServer(TEST_HOSTNAME);
    }

    // ==================== Lazy Eviction Tests ====================

    @Test
    @DisplayName("Should lazily remove expired server entry on cache miss")
    void shouldLazilyRemoveExpiredServerEntryOnCacheMiss() throws InterruptedException {
        // Given - very short TTL
        cachingService = CachingBadgeVerificationService.builder()
            .delegate(delegate)
            .cacheTtl(Duration.ofMillis(50))
            .build();

        ServerVerificationResult result = createSuccessfulServerResult();
        when(delegate.verifyServer(TEST_HOSTNAME)).thenReturn(result);

        // Populate cache
        cachingService.verifyServer(TEST_HOSTNAME);
        assertThat(cachingService.serverCacheSize()).isEqualTo(1);

        // Wait for expiry
        Thread.sleep(100);

        // Cache still has 1 entry (expired but not evicted yet)
        assertThat(cachingService.serverCacheSize()).isEqualTo(1);

        // When - access expired entry (should trigger lazy eviction + refresh)
        cachingService.verifyServer(TEST_HOSTNAME);

        // Then - expired entry was removed and replaced with fresh one
        // Cache size should still be 1 (the new entry)
        assertThat(cachingService.serverCacheSize()).isEqualTo(1);

        // And delegate was called twice (initial + refresh after expiry)
        verify(delegate, times(2)).verifyServer(TEST_HOSTNAME);
    }

    @Test
    @DisplayName("Should lazily remove expired client entry on cache miss")
    void shouldLazilyRemoveExpiredClientEntryOnCacheMiss() throws Exception {
        // Given - very short TTL
        cachingService = CachingBadgeVerificationService.builder()
            .delegate(delegate)
            .cacheTtl(Duration.ofMillis(50))
            .build();

        byte[] certBytes = "test-cert-bytes".getBytes();
        when(mockCertificate.getEncoded()).thenReturn(certBytes);

        ClientVerificationResult result = createSuccessfulClientResult();
        when(delegate.verifyClient(mockCertificate)).thenReturn(result);

        // Populate cache
        cachingService.verifyClient(mockCertificate);
        assertThat(cachingService.clientCacheSize()).isEqualTo(1);

        // Wait for expiry
        Thread.sleep(100);

        // Cache still has 1 entry (expired but not evicted yet)
        assertThat(cachingService.clientCacheSize()).isEqualTo(1);

        // When - access expired entry (should trigger lazy eviction + refresh)
        cachingService.verifyClient(mockCertificate);

        // Then - expired entry was removed and replaced with fresh one
        assertThat(cachingService.clientCacheSize()).isEqualTo(1);

        // And delegate was called twice
        verify(delegate, times(2)).verifyClient(mockCertificate);
    }

    @Test
    @DisplayName("Should remove expired entry immediately when accessed, not wait for put")
    void shouldRemoveExpiredEntryImmediatelyWhenAccessed() throws InterruptedException {
        // This test verifies that expired entries are REMOVED when found,
        // not just overwritten by a subsequent put. This matters for memory
        // because the old CachedResult object should be eligible for GC immediately.

        // Given - very short TTL
        cachingService = CachingBadgeVerificationService.builder()
            .delegate(delegate)
            .cacheTtl(Duration.ofMillis(50))
            .build();

        // Mock delegate to throw on second call - this way we can verify
        // that removal happens even when the refresh fails
        ServerVerificationResult firstResult = createSuccessfulServerResult();
        when(delegate.verifyServer(TEST_HOSTNAME))
            .thenReturn(firstResult)
            .thenThrow(new RuntimeException("Network error"));

        // Populate cache
        cachingService.verifyServer(TEST_HOSTNAME);
        assertThat(cachingService.serverCacheSize()).isEqualTo(1);

        // Wait for expiry
        Thread.sleep(100);

        // When - access expired entry (refresh will fail)
        try {
            cachingService.verifyServer(TEST_HOSTNAME);
        } catch (RuntimeException e) {
            // Expected - delegate threw
        }

        // Then - expired entry should have been removed BEFORE the failed refresh
        // So cache should be empty (not still holding the stale entry)
        assertThat(cachingService.serverCacheSize()).isEqualTo(0);
    }

    // ==================== Helper Methods ====================

    private ServerVerificationResult createSuccessfulServerResult() {
        TransparencyLog registration = createMockRegistration("ACTIVE");
        return ServerVerificationResult.builder()
            .status(VerificationStatus.VERIFIED)
            .expectedServerCertFingerprint(TEST_FINGERPRINT)
            .expectedAgentHost(TEST_HOSTNAME)
            .registration(registration)
            .build();
    }

    private ServerVerificationResult createFailedServerResult() {
        return ServerVerificationResult.builder()
            .status(VerificationStatus.LOOKUP_FAILED)
            .warningMessage("Network error: Connection timeout")
            .build();
    }

    private ClientVerificationResult createSuccessfulClientResult() {
        TransparencyLog registration = createMockRegistration("ACTIVE");
        return ClientVerificationResult.builder()
            .status(VerificationStatus.VERIFIED)
            .expectedIdentityCertFingerprint(TEST_FINGERPRINT)
            .expectedAnsName(TEST_ANS_NAME)
            .expectedAgentHost(TEST_HOSTNAME)
            .registration(registration)
            .build();
    }

    private TransparencyLog createMockRegistration(String status) {
        CertificateInfo serverCert = new CertificateInfo();
        serverCert.setFingerprint(TEST_FINGERPRINT);
        serverCert.setType(CertType.X509_DV_SERVER);

        CertificateInfo identityCert = new CertificateInfo();
        identityCert.setFingerprint(TEST_FINGERPRINT);
        identityCert.setType(CertType.X509_OV_CLIENT);

        AttestationsV1 attestations = new AttestationsV1();
        attestations.setServerCert(serverCert);
        attestations.setIdentityCert(identityCert);

        AgentV1 agent = new AgentV1();
        agent.setHost(TEST_HOSTNAME);
        agent.setName("Test Agent");
        agent.setVersion("v1.0.0");

        EventV1 event = new EventV1();
        event.setAnsName(TEST_ANS_NAME);
        event.setAgent(agent);
        event.setAttestations(attestations);

        ProducerV1 producer = new ProducerV1();
        producer.setEvent(event);

        TransparencyLogV1 v1Payload = new TransparencyLogV1();
        v1Payload.setLogId("log-123");
        v1Payload.setProducer(producer);

        TransparencyLog log = new TransparencyLog();
        log.setStatus(status);
        log.setSchemaVersion("V1");
        log.setParsedPayload(v1Payload);

        return log;
    }
}
