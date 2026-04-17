package com.godaddy.ans.sdk.agent.http;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for CertificateCapturingTrustManager.
 */
class CertificateCapturingTrustManagerTest {

    private X509TrustManager mockDelegate;
    private X509ExtendedTrustManager mockExtendedDelegate;
    private X509Certificate mockCert;
    private X509Certificate[] certChain;

    @BeforeEach
    void setUp() {
        mockDelegate = mock(X509TrustManager.class);
        mockExtendedDelegate = mock(X509ExtendedTrustManager.class);
        mockCert = mock(X509Certificate.class);
        certChain = new X509Certificate[]{mockCert};
    }

    @Test
    void constructorRequiresNonNullDelegate() {
        assertThrows(NullPointerException.class, () ->
            new CertificateCapturingTrustManager(null));
    }

    @Test
    void constructorAcceptsValidDelegate() {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockDelegate);
        assertNotNull(tm);
    }

    @Test
    void getInstanceCapturedCertificatesReturnsNullForUnknownHost() {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockDelegate);
        assertNull(tm.getInstanceCapturedCertificates("unknown.host.com"));
    }

    @Test
    void clearInstanceCapturedCertificatesRemovesCertificates() throws CertificateException {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockExtendedDelegate);
        SSLEngine engine = mock(SSLEngine.class);
        when(engine.getPeerHost()).thenReturn("test.example.com");

        tm.checkServerTrusted(certChain, "RSA", engine);

        assertNotNull(tm.getInstanceCapturedCertificates("test.example.com"));
        // After get (which removes), clear should be a no-op
        tm.clearInstanceCapturedCertificates("test.example.com");
        assertNull(tm.getInstanceCapturedCertificates("test.example.com"));
    }

    @Test
    void clearInstanceCapturedCertificatesRemovesBeforeGet() throws CertificateException {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockExtendedDelegate);
        SSLEngine engine = mock(SSLEngine.class);
        when(engine.getPeerHost()).thenReturn("test.example.com");

        tm.checkServerTrusted(certChain, "RSA", engine);

        // Clear before get
        tm.clearInstanceCapturedCertificates("test.example.com");
        assertNull(tm.getInstanceCapturedCertificates("test.example.com"));
    }

    @Test
    void clearAllInstanceCapturedCertificates() throws CertificateException {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockExtendedDelegate);
        SSLEngine engine1 = mock(SSLEngine.class);
        when(engine1.getPeerHost()).thenReturn("host1.com");
        SSLEngine engine2 = mock(SSLEngine.class);
        when(engine2.getPeerHost()).thenReturn("host2.com");

        tm.checkServerTrusted(certChain, "RSA", engine1);
        tm.checkServerTrusted(certChain, "RSA", engine2);

        tm.clearInstanceCapturedCertificates();

        assertNull(tm.getInstanceCapturedCertificates("host1.com"));
        assertNull(tm.getInstanceCapturedCertificates("host2.com"));
    }

    @Test
    void checkServerTrustedWithEngineCaptures() throws CertificateException {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockExtendedDelegate);
        SSLEngine engine = mock(SSLEngine.class);
        when(engine.getPeerHost()).thenReturn("secure.example.com");

        tm.checkServerTrusted(certChain, "RSA", engine);

        verify(mockExtendedDelegate).checkServerTrusted(certChain, "RSA", engine);
        X509Certificate[] captured = tm.getInstanceCapturedCertificates("secure.example.com");
        assertNotNull(captured);
        assertEquals(1, captured.length);
    }

    @Test
    void checkServerTrustedWithSocketCaptures() throws CertificateException {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockExtendedDelegate);
        Socket socket = mock(Socket.class);
        when(socket.getRemoteSocketAddress()).thenReturn(new InetSocketAddress("socket.example.com", 443));

        tm.checkServerTrusted(certChain, "RSA", socket);

        verify(mockExtendedDelegate).checkServerTrusted(certChain, "RSA", socket);
        X509Certificate[] captured = tm.getInstanceCapturedCertificates("socket.example.com");
        assertNotNull(captured);
    }

    @Test
    void checkServerTrustedDelegatesToBasicTrustManager() throws CertificateException {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockDelegate);
        Socket socket = mock(Socket.class);
        when(socket.getRemoteSocketAddress()).thenReturn(new InetSocketAddress("basic.example.com", 443));

        tm.checkServerTrusted(certChain, "RSA", socket);

        // Non-extended delegate should use basic method
        verify(mockDelegate).checkServerTrusted(certChain, "RSA");
    }

    @Test
    void checkClientTrustedDelegates() throws CertificateException {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockDelegate);

        tm.checkClientTrusted(certChain, "RSA");

        verify(mockDelegate).checkClientTrusted(certChain, "RSA");
    }

    @Test
    void checkClientTrustedWithSocketDelegatesToExtended() throws CertificateException {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockExtendedDelegate);
        Socket socket = mock(Socket.class);

        tm.checkClientTrusted(certChain, "RSA", socket);

        verify(mockExtendedDelegate).checkClientTrusted(certChain, "RSA", socket);
    }

    @Test
    void checkClientTrustedWithEngineDelegatesToExtended() throws CertificateException {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockExtendedDelegate);
        SSLEngine engine = mock(SSLEngine.class);

        tm.checkClientTrusted(certChain, "RSA", engine);

        verify(mockExtendedDelegate).checkClientTrusted(certChain, "RSA", engine);
    }

    @Test
    void getAcceptedIssuersDelegates() {
        X509Certificate[] issuers = new X509Certificate[]{mockCert};
        when(mockDelegate.getAcceptedIssuers()).thenReturn(issuers);
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockDelegate);

        X509Certificate[] result = tm.getAcceptedIssuers();

        assertArrayEquals(issuers, result);
        verify(mockDelegate).getAcceptedIssuers();
    }

    @Test
    void capturedCertificatesAreCloned() throws CertificateException {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockExtendedDelegate);

        // First handshake
        SSLEngine engine1 = mock(SSLEngine.class);
        SSLSession session1 = mock(SSLSession.class);
        when(engine1.getPeerHost()).thenReturn("clone.test.com");
        when(engine1.getSession()).thenReturn(session1);
        when(session1.getId()).thenReturn(new byte[]{0x01});
        tm.checkServerTrusted(certChain, "RSA", engine1);

        // Second handshake (same host, different session)
        SSLEngine engine2 = mock(SSLEngine.class);
        SSLSession session2 = mock(SSLSession.class);
        when(engine2.getPeerHost()).thenReturn("clone.test.com");
        when(engine2.getSession()).thenReturn(session2);
        when(session2.getId()).thenReturn(new byte[]{0x02});
        tm.checkServerTrusted(certChain, "RSA", engine2);

        X509Certificate[] captured1 = tm.getInstanceCapturedCertificates("clone.test.com");
        X509Certificate[] captured2 = tm.getInstanceCapturedCertificates("clone.test.com");

        assertNotNull(captured1);
        assertNotNull(captured2);
        assertNotSame(captured1, captured2);
    }

    @Test
    void delegateExceptionPropagates() throws CertificateException {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockExtendedDelegate);
        SSLEngine engine = mock(SSLEngine.class);
        when(engine.getPeerHost()).thenReturn("fail.test.com");

        doThrow(new CertificateException("Untrusted"))
            .when(mockExtendedDelegate).checkServerTrusted(any(), eq("RSA"), eq(engine));

        assertThrows(CertificateException.class, () ->
            tm.checkServerTrusted(certChain, "RSA", engine));
    }

    @Test
    void checkServerTrustedWithoutSocketOrEngine() throws CertificateException {
        // Test the basic checkServerTrusted without socket/engine - uses subject-based capture
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockDelegate);

        tm.checkServerTrusted(certChain, "RSA");

        verify(mockDelegate).checkServerTrusted(certChain, "RSA");
    }

    @Test
    void checkServerTrustedWithNullHostnameFromEngine() throws CertificateException {
        // Test when SSLEngine returns null peer host - should use subject-based capture
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockExtendedDelegate);
        SSLEngine engine = mock(SSLEngine.class);
        when(engine.getPeerHost()).thenReturn(null);

        tm.checkServerTrusted(certChain, "RSA", engine);

        verify(mockExtendedDelegate).checkServerTrusted(certChain, "RSA", engine);
    }

    @Test
    void checkServerTrustedWithNullHostnameFromSocket() throws CertificateException {
        // Test when Socket returns non-InetSocketAddress - should use subject-based capture
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockExtendedDelegate);
        Socket socket = mock(Socket.class);
        when(socket.getRemoteSocketAddress()).thenReturn(null);

        tm.checkServerTrusted(certChain, "RSA", socket);

        verify(mockExtendedDelegate).checkServerTrusted(certChain, "RSA", socket);
    }

    @Test
    void checkServerTrustedWithEmptyCertChain() throws CertificateException {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockExtendedDelegate);
        SSLEngine engine = mock(SSLEngine.class);
        when(engine.getPeerHost()).thenReturn("empty.test.com");

        tm.checkServerTrusted(new X509Certificate[0], "RSA", engine);

        assertNull(tm.getInstanceCapturedCertificates("empty.test.com"));
    }

    @Test
    void checkServerTrustedWithNullCertChain() throws CertificateException {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockExtendedDelegate);
        SSLEngine engine = mock(SSLEngine.class);
        when(engine.getPeerHost()).thenReturn("null.test.com");

        tm.checkServerTrusted(null, "RSA", engine);

        assertNull(tm.getInstanceCapturedCertificates("null.test.com"));
    }

    @Test
    void checkClientTrustedWithSocketDelegatesToBasic() throws CertificateException {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockDelegate);
        Socket socket = mock(Socket.class);

        tm.checkClientTrusted(certChain, "RSA", socket);

        // Non-extended delegate should use basic method
        verify(mockDelegate).checkClientTrusted(certChain, "RSA");
    }

    @Test
    void checkClientTrustedWithEngineDelegatesToBasic() throws CertificateException {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockDelegate);
        SSLEngine engine = mock(SSLEngine.class);

        tm.checkClientTrusted(certChain, "RSA", engine);

        // Non-extended delegate should use basic method
        verify(mockDelegate).checkClientTrusted(certChain, "RSA");
    }

    @Test
    void checkServerTrustedWithEngineDelegatesToBasic() throws CertificateException {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockDelegate);
        SSLEngine engine = mock(SSLEngine.class);
        when(engine.getPeerHost()).thenReturn("basic-engine.test.com");

        tm.checkServerTrusted(certChain, "RSA", engine);

        // Non-extended delegate should use basic method
        verify(mockDelegate).checkServerTrusted(certChain, "RSA");
        X509Certificate[] captured = tm.getInstanceCapturedCertificates("basic-engine.test.com");
        assertNotNull(captured);
    }

    // ==================== Session ID-based Tests ====================

    @Test
    void getCapturedCertificatesWithSessionId() throws CertificateException {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockExtendedDelegate);
        SSLEngine engine = mock(SSLEngine.class);
        SSLSession session = mock(SSLSession.class);
        when(engine.getPeerHost()).thenReturn("session.test.com");
        when(engine.getSession()).thenReturn(session);
        when(session.getId()).thenReturn(new byte[]{0x01, 0x02, 0x03, 0x04});

        tm.checkServerTrusted(certChain, "RSA", engine);

        // Should be able to retrieve with hostname only (finds first match)
        X509Certificate[] captured = tm.getInstanceCapturedCertificates("session.test.com");
        assertNotNull(captured);
    }

    @Test
    void clearCapturedCertificatesWithSessionIdClearsForHostname() throws CertificateException {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockExtendedDelegate);
        SSLEngine engine = mock(SSLEngine.class);
        SSLSession session = mock(SSLSession.class);
        when(engine.getPeerHost()).thenReturn("clear.session.test.com");
        when(engine.getSession()).thenReturn(session);
        when(session.getId()).thenReturn(new byte[]{0x11, 0x22, 0x33, 0x44});

        tm.checkServerTrusted(certChain, "RSA", engine);

        // Clear by hostname (clears all session IDs)
        tm.clearInstanceCapturedCertificates("clear.session.test.com");

        // Should be cleared
        assertNull(tm.getInstanceCapturedCertificates("clear.session.test.com"));
    }

    @Test
    void extractSessionIdHandlesExceptionGracefully() throws CertificateException {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockExtendedDelegate);
        SSLEngine engine = mock(SSLEngine.class);
        when(engine.getPeerHost()).thenReturn("exception.test.com");
        when(engine.getSession()).thenThrow(new RuntimeException("Session error"));

        // Should not throw - falls back to identity hash
        tm.checkServerTrusted(certChain, "RSA", engine);

        X509Certificate[] captured = tm.getInstanceCapturedCertificates("exception.test.com");
        assertNotNull(captured);
    }

    @Test
    void extractSessionIdHandlesEmptySessionId() throws CertificateException {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockExtendedDelegate);
        SSLEngine engine = mock(SSLEngine.class);
        SSLSession session = mock(SSLSession.class);
        when(engine.getPeerHost()).thenReturn("emptysid.test.com");
        when(engine.getSession()).thenReturn(session);
        when(session.getId()).thenReturn(new byte[0]); // Empty session ID

        tm.checkServerTrusted(certChain, "RSA", engine);

        X509Certificate[] captured = tm.getInstanceCapturedCertificates("emptysid.test.com");
        assertNotNull(captured);
    }

    @Test
    void extractSessionIdHandlesNullSessionId() throws CertificateException {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockExtendedDelegate);
        SSLEngine engine = mock(SSLEngine.class);
        SSLSession session = mock(SSLSession.class);
        when(engine.getPeerHost()).thenReturn("nullsid.test.com");
        when(engine.getSession()).thenReturn(session);
        when(session.getId()).thenReturn(null); // Null session ID

        tm.checkServerTrusted(certChain, "RSA", engine);

        X509Certificate[] captured = tm.getInstanceCapturedCertificates("nullsid.test.com");
        assertNotNull(captured);
    }

    @Test
    void concurrentRequestsToSameHostGetSeparateCertificates() throws CertificateException {
        CertificateCapturingTrustManager tm = new CertificateCapturingTrustManager(mockExtendedDelegate);

        // First request with session ID 1
        SSLEngine engine1 = mock(SSLEngine.class);
        SSLSession session1 = mock(SSLSession.class);
        when(engine1.getPeerHost()).thenReturn("concurrent.test.com");
        when(engine1.getSession()).thenReturn(session1);
        when(session1.getId()).thenReturn(new byte[]{0x01});

        X509Certificate cert1 = mock(X509Certificate.class);
        X509Certificate[] chain1 = new X509Certificate[]{cert1};

        // Second request with session ID 2 (same host)
        SSLEngine engine2 = mock(SSLEngine.class);
        SSLSession session2 = mock(SSLSession.class);
        when(engine2.getPeerHost()).thenReturn("concurrent.test.com");
        when(engine2.getSession()).thenReturn(session2);
        when(session2.getId()).thenReturn(new byte[]{0x02});

        X509Certificate cert2 = mock(X509Certificate.class);
        X509Certificate[] chain2 = new X509Certificate[]{cert2};

        // Both handshakes complete
        tm.checkServerTrusted(chain1, "RSA", engine1);
        tm.checkServerTrusted(chain2, "RSA", engine2);

        // Each retrieval should get one certificate (removed on retrieval)
        X509Certificate[] captured1 = tm.getInstanceCapturedCertificates("concurrent.test.com");
        X509Certificate[] captured2 = tm.getInstanceCapturedCertificates("concurrent.test.com");

        assertNotNull(captured1);
        assertNotNull(captured2);
        // After two retrievals, should be empty
        assertNull(tm.getInstanceCapturedCertificates("concurrent.test.com"));
    }

    @Test
    void instanceCachesShouldBeIsolated() throws CertificateException {
        // Two separate trust managers should have isolated instance caches
        CertificateCapturingTrustManager tm1 =
            new CertificateCapturingTrustManager(mockExtendedDelegate);
        CertificateCapturingTrustManager tm2 =
            new CertificateCapturingTrustManager(mockExtendedDelegate);

        SSLEngine engine = mock(SSLEngine.class);
        when(engine.getPeerHost()).thenReturn("isolated.example.com");

        // Only tm1 captures a certificate
        tm1.checkServerTrusted(certChain, "RSA", engine);

        // tm1's instance cache should have the certificate
        assertNotNull(tm1.getInstanceCapturedCertificates("isolated.example.com"));

        // tm2's instance cache should NOT have it
        assertNull(tm2.getInstanceCapturedCertificates("isolated.example.com"));
    }
}