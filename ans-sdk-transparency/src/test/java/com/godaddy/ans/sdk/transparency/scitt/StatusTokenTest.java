package com.godaddy.ans.sdk.transparency.scitt;

import com.godaddy.ans.sdk.transparency.model.CertificateInfo;
import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class StatusTokenTest {

    @Nested
    @DisplayName("CwtClaims tests")
    class CwtClaimsTests {

        @Test
        @DisplayName("Should convert epoch seconds to Instant")
        void shouldConvertEpochToInstant() {
            CwtClaims claims = new CwtClaims(
                "issuer", "subject", "audience",
                1700000000L, 1600000000L, 1650000000L);

            assertThat(claims.expirationTime()).isEqualTo(Instant.ofEpochSecond(1700000000L));
            assertThat(claims.notBeforeTime()).isEqualTo(Instant.ofEpochSecond(1600000000L));
            assertThat(claims.issuedAtTime()).isEqualTo(Instant.ofEpochSecond(1650000000L));
        }

        @Test
        @DisplayName("Should return null for missing timestamps")
        void shouldReturnNullForMissingTimestamps() {
            CwtClaims claims = new CwtClaims("issuer", null, null, null, null, null);

            assertThat(claims.expirationTime()).isNull();
            assertThat(claims.notBeforeTime()).isNull();
            assertThat(claims.issuedAtTime()).isNull();
        }

        @Test
        @DisplayName("Should check expiration correctly")
        void shouldCheckExpirationCorrectly() {
            long futureExp = Instant.now().plusSeconds(3600).getEpochSecond();
            long pastExp = Instant.now().minusSeconds(3600).getEpochSecond();

            CwtClaims futureClaims = new CwtClaims(null, null, null, futureExp, null, null);
            CwtClaims pastClaims = new CwtClaims(null, null, null, pastExp, null, null);
            CwtClaims noClaims = new CwtClaims(null, null, null, null, null, null);

            assertThat(futureClaims.isExpired(Instant.now())).isFalse();
            assertThat(pastClaims.isExpired(Instant.now())).isTrue();
            assertThat(noClaims.isExpired(Instant.now())).isFalse();
        }

        @Test
        @DisplayName("Should check expiration with clock skew")
        void shouldCheckExpirationWithClockSkew() {
            // Token that expired 30 seconds ago
            long exp = Instant.now().minusSeconds(30).getEpochSecond();
            CwtClaims claims = new CwtClaims(null, null, null, exp, null, null);

            // Without clock skew, it's expired
            assertThat(claims.isExpired(Instant.now(), 0)).isTrue();

            // With 60 second clock skew, it's still valid
            assertThat(claims.isExpired(Instant.now(), 60)).isFalse();
        }

        @Test
        @DisplayName("Should check not-before correctly")
        void shouldCheckNotBeforeCorrectly() {
            long futureNbf = Instant.now().plusSeconds(3600).getEpochSecond();
            long pastNbf = Instant.now().minusSeconds(3600).getEpochSecond();

            CwtClaims futureClaims = new CwtClaims(null, null, null, null, futureNbf, null);
            CwtClaims pastClaims = new CwtClaims(null, null, null, null, pastNbf, null);

            assertThat(futureClaims.isNotYetValid(Instant.now())).isTrue();
            assertThat(pastClaims.isNotYetValid(Instant.now())).isFalse();
        }

        @Test
        @DisplayName("Should check not-before with clock skew")
        void shouldCheckNotBeforeWithClockSkew() {
            // Token that becomes valid 30 seconds from now
            long nbf = Instant.now().plusSeconds(30).getEpochSecond();
            CwtClaims claims = new CwtClaims(null, null, null, null, nbf, null);

            // Without clock skew, it's not yet valid
            assertThat(claims.isNotYetValid(Instant.now(), 0)).isTrue();

            // With 60 second clock skew, it's valid
            assertThat(claims.isNotYetValid(Instant.now(), 60)).isFalse();
        }
    }

    @Nested
    @DisplayName("StatusToken expiry tests")
    class StatusTokenExpiryTests {

        @Test
        @DisplayName("Should check token expiration")
        void shouldCheckTokenExpiration() {
            Instant past = Instant.now().minusSeconds(3600);
            Instant future = Instant.now().plusSeconds(3600);

            StatusToken expiredToken = createToken("id", StatusToken.Status.ACTIVE, past, past);
            StatusToken validToken = createToken("id", StatusToken.Status.ACTIVE, past, future);

            assertThat(expiredToken.isExpired()).isTrue();
            assertThat(validToken.isExpired()).isFalse();
        }

        @Test
        @DisplayName("Should respect clock skew tolerance")
        void shouldRespectClockSkewTolerance() {
            // Token expired 30 seconds ago
            Instant past = Instant.now().minusSeconds(3600);
            Instant recentExpiry = Instant.now().minusSeconds(30);

            StatusToken token = createToken("id", StatusToken.Status.ACTIVE, past, recentExpiry);

            // With default 60s clock skew, should not be expired
            assertThat(token.isExpired(Duration.ofSeconds(60))).isFalse();

            // With 0 clock skew, should be expired
            assertThat(token.isExpired(Duration.ZERO)).isTrue();
        }

        @Test
        @DisplayName("Should treat null expiry as expired (defensive)")
        void shouldTreatNullExpiryAsExpired() {
            // Direct construction with null expiry is treated as expired (defensive check)
            // Normal parsing would reject such tokens
            StatusToken token = createToken("id", StatusToken.Status.ACTIVE, Instant.now(), null);
            assertThat(token.isExpired()).isTrue();
        }
    }

    @Nested
    @DisplayName("StatusToken refresh interval tests")
    class RefreshIntervalTests {

        @Test
        @DisplayName("Should compute refresh interval as half of lifetime")
        void shouldComputeRefreshIntervalAsHalfLifetime() {
            Instant issuedAt = Instant.now();
            Instant expiresAt = issuedAt.plusSeconds(7200);  // 2 hours

            StatusToken token = createToken("id", StatusToken.Status.ACTIVE, issuedAt, expiresAt);

            Duration interval = token.computeRefreshInterval();
            assertThat(interval).isEqualTo(Duration.ofSeconds(3600));  // 1 hour
        }

        @Test
        @DisplayName("Should return minimum 1 minute interval")
        void shouldReturnMinimumInterval() {
            Instant issuedAt = Instant.now();
            Instant expiresAt = issuedAt.plusSeconds(30);  // 30 seconds

            StatusToken token = createToken("id", StatusToken.Status.ACTIVE, issuedAt, expiresAt);

            Duration interval = token.computeRefreshInterval();
            assertThat(interval).isEqualTo(Duration.ofMinutes(1));
        }

        @Test
        @DisplayName("Should return maximum 1 hour interval")
        void shouldReturnMaximumInterval() {
            Instant issuedAt = Instant.now();
            Instant expiresAt = issuedAt.plusSeconds(86400);  // 24 hours

            StatusToken token = createToken("id", StatusToken.Status.ACTIVE, issuedAt, expiresAt);

            Duration interval = token.computeRefreshInterval();
            assertThat(interval).isEqualTo(Duration.ofHours(1));
        }

        @Test
        @DisplayName("Should return default for missing timestamps")
        void shouldReturnDefaultForMissingTimestamps() {
            StatusToken token = createToken("id", StatusToken.Status.ACTIVE, null, null);

            Duration interval = token.computeRefreshInterval();
            assertThat(interval).isEqualTo(Duration.ofMinutes(5));
        }
    }

    @Nested
    @DisplayName("StatusToken status tests")
    class StatusTests {

        @Test
        @DisplayName("Should parse all status values")
        void shouldParseAllStatusValues() {
            assertThat(StatusToken.Status.valueOf("ACTIVE")).isEqualTo(StatusToken.Status.ACTIVE);
            assertThat(StatusToken.Status.valueOf("WARNING")).isEqualTo(StatusToken.Status.WARNING);
            assertThat(StatusToken.Status.valueOf("DEPRECATED")).isEqualTo(StatusToken.Status.DEPRECATED);
            assertThat(StatusToken.Status.valueOf("EXPIRED")).isEqualTo(StatusToken.Status.EXPIRED);
            assertThat(StatusToken.Status.valueOf("REVOKED")).isEqualTo(StatusToken.Status.REVOKED);
            assertThat(StatusToken.Status.valueOf("UNKNOWN")).isEqualTo(StatusToken.Status.UNKNOWN);
        }
    }

    @Nested
    @DisplayName("StatusToken parsing tests")
    class ParsingTests {

        @Test
        @DisplayName("Should reject null input")
        void shouldRejectNullInput() {
            assertThatThrownBy(() -> StatusToken.parse(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("coseBytes cannot be null");
        }

        @Test
        @DisplayName("Should reject empty payload")
        void shouldRejectEmptyPayload() throws Exception {
            byte[] coseBytes = createCoseSign1WithPayload(new byte[0]);

            assertThatThrownBy(() -> StatusToken.parse(coseBytes))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("payload cannot be empty");
        }

        @Test
        @DisplayName("Should reject non-map payload")
        void shouldRejectNonMapPayload() throws Exception {
            CBORObject array = CBORObject.NewArray();
            array.Add("test");
            byte[] coseBytes = createCoseSign1WithPayload(array.EncodeToBytes());

            assertThatThrownBy(() -> StatusToken.parse(coseBytes))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("must be a CBOR map");
        }

        @Test
        @DisplayName("Should reject missing agent_id")
        void shouldRejectMissingAgentId() throws Exception {
            CBORObject payload = CBORObject.NewMap();
            payload.Add(2, "ACTIVE");  // status only, no agent_id
            byte[] coseBytes = createCoseSign1WithPayload(payload.EncodeToBytes());

            assertThatThrownBy(() -> StatusToken.parse(coseBytes))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Missing required field");
        }

        @Test
        @DisplayName("Should reject missing status")
        void shouldRejectMissingStatus() throws Exception {
            CBORObject payload = CBORObject.NewMap();
            payload.Add(1, "test-agent");  // agent_id only, no status
            byte[] coseBytes = createCoseSign1WithPayload(payload.EncodeToBytes());

            assertThatThrownBy(() -> StatusToken.parse(coseBytes))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Missing required field");
        }

        @Test
        @DisplayName("Should reject missing expiration")
        void shouldRejectMissingExpiration() throws Exception {
            CBORObject payload = CBORObject.NewMap();
            payload.Add(1, "test-agent");  // agent_id
            payload.Add(2, "ACTIVE");      // status - no exp
            byte[] coseBytes = createCoseSign1WithPayload(payload.EncodeToBytes());

            assertThatThrownBy(() -> StatusToken.parse(coseBytes))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("missing required expiration time");
        }

        @Test
        @DisplayName("Should parse minimal valid token")
        void shouldParseMinimalValidToken() throws Exception {
            long future = Instant.now().plusSeconds(3600).getEpochSecond();

            CBORObject payload = CBORObject.NewMap();
            payload.Add(1, "test-agent");  // agent_id
            payload.Add(2, "ACTIVE");      // status
            payload.Add(4, future);        // exp (required)
            byte[] coseBytes = createCoseSign1WithPayload(payload.EncodeToBytes());

            StatusToken token = StatusToken.parse(coseBytes);

            assertThat(token.agentId()).isEqualTo("test-agent");
            assertThat(token.status()).isEqualTo(StatusToken.Status.ACTIVE);
            assertThat(token.expiresAt()).isNotNull();
        }

        @Test
        @DisplayName("Should parse token with all fields")
        void shouldParseTokenWithAllFields() throws Exception {
            long now = Instant.now().getEpochSecond();
            long future = now + 3600;

            CBORObject payload = CBORObject.NewMap();
            payload.Add(1, "test-agent");       // agent_id
            payload.Add(2, "WARNING");          // status
            payload.Add(3, now);                // iat
            payload.Add(4, future);             // exp
            payload.Add(5, "test.agent.ans");   // ans_name

            // Add server certs (key 7)
            CBORObject serverCerts = CBORObject.NewArray();
            CBORObject cert = CBORObject.NewMap();
            cert.Add(1, "abc123");    // fingerprint
            cert.Add(2, "LEAF");      // type
            serverCerts.Add(cert);
            payload.Add(7, serverCerts);

            // Add identity certs (key 6) as simple strings
            CBORObject identityCerts = CBORObject.NewArray();
            identityCerts.Add("def456");
            payload.Add(6, identityCerts);

            // Add metadata hashes (key 8)
            CBORObject metadataHashes = CBORObject.NewMap();
            metadataHashes.Add("a2a", "SHA256:hash1");
            metadataHashes.Add("mcp", "SHA256:hash2");
            payload.Add(8, metadataHashes);

            byte[] coseBytes = createCoseSign1WithPayload(payload.EncodeToBytes());

            StatusToken token = StatusToken.parse(coseBytes);

            assertThat(token.agentId()).isEqualTo("test-agent");
            assertThat(token.status()).isEqualTo(StatusToken.Status.WARNING);
            assertThat(token.ansName()).isEqualTo("test.agent.ans");
            assertThat(token.issuedAt()).isEqualTo(Instant.ofEpochSecond(now));
            assertThat(token.expiresAt()).isEqualTo(Instant.ofEpochSecond(future));
            assertThat(token.validServerCerts()).hasSize(1);
            assertThat(token.validIdentityCerts()).hasSize(1);
            assertThat(token.metadataHashes()).hasSize(2);
        }

        @Test
        @DisplayName("Should parse unknown status as UNKNOWN")
        void shouldParseUnknownStatusAsUnknown() throws Exception {
            long future = Instant.now().plusSeconds(3600).getEpochSecond();

            CBORObject payload = CBORObject.NewMap();
            payload.Add(1, "test-agent");     // agent_id
            payload.Add(2, "BOGUS_STATUS");   // status
            payload.Add(4, future);           // exp (required)
            byte[] coseBytes = createCoseSign1WithPayload(payload.EncodeToBytes());

            StatusToken token = StatusToken.parse(coseBytes);

            assertThat(token.status()).isEqualTo(StatusToken.Status.UNKNOWN);
        }

        private byte[] createCoseSign1WithPayload(byte[] payload) {
            CBORObject protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(1, -7);  // alg = ES256
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(CBORObject.NewMap());
            array.Add(payload);
            array.Add(new byte[64]);  // signature
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            return tagged.EncodeToBytes();
        }
    }

    @Nested
    @DisplayName("Certificate fingerprint accessor tests")
    class FingerprintAccessorTests {

        @Test
        @DisplayName("Should return server cert fingerprints")
        void shouldReturnServerCertFingerprints() {
            CertificateInfo cert1 = new CertificateInfo();
            cert1.setFingerprint("fp1");
            CertificateInfo cert2 = new CertificateInfo();
            cert2.setFingerprint("fp2");

            StatusToken token = new StatusToken(
                "id", StatusToken.Status.ACTIVE, null, null,
                null, null, List.of(), List.of(cert1, cert2),
                Map.of(), null, null, null, null
            );

            assertThat(token.serverCertFingerprints()).containsExactly("fp1", "fp2");
        }

        @Test
        @DisplayName("Should return identity cert fingerprints")
        void shouldReturnIdentityCertFingerprints() {
            CertificateInfo cert1 = new CertificateInfo();
            cert1.setFingerprint("id1");
            CertificateInfo cert2 = new CertificateInfo();
            cert2.setFingerprint("id2");

            StatusToken token = new StatusToken(
                "id", StatusToken.Status.ACTIVE, null, null,
                null, null, List.of(cert1, cert2), List.of(),
                Map.of(), null, null, null, null
            );

            assertThat(token.identityCertFingerprints()).containsExactly("id1", "id2");
        }

        @Test
        @DisplayName("Should filter null fingerprints")
        void shouldFilterNullFingerprints() {
            CertificateInfo cert1 = new CertificateInfo();
            cert1.setFingerprint("fp1");
            CertificateInfo cert2 = new CertificateInfo();
            // No fingerprint set

            StatusToken token = new StatusToken(
                "id", StatusToken.Status.ACTIVE, null, null,
                null, null, List.of(), List.of(cert1, cert2),
                Map.of(), null, null, null, null
            );

            assertThat(token.serverCertFingerprints()).containsExactly("fp1");
        }
    }

    @Nested
    @DisplayName("Equals and hashCode tests")
    class EqualsHashCodeTests {

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            StatusToken token = createToken("id", StatusToken.Status.ACTIVE, Instant.now(),
                    Instant.now().plusSeconds(3600));
            assertThat(token).isEqualTo(token);
        }

        @Test
        @DisplayName("Should be equal for same values")
        void shouldBeEqualForSameValues() {
            Instant now = Instant.now();
            Instant later = now.plusSeconds(3600);

            StatusToken token1 = createToken("id", StatusToken.Status.ACTIVE, now, later);
            StatusToken token2 = createToken("id", StatusToken.Status.ACTIVE, now, later);

            assertThat(token1).isEqualTo(token2);
            assertThat(token1.hashCode()).isEqualTo(token2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal for different agent IDs")
        void shouldNotBeEqualForDifferentIds() {
            Instant now = Instant.now();
            Instant later = now.plusSeconds(3600);

            StatusToken token1 = createToken("id1", StatusToken.Status.ACTIVE, now, later);
            StatusToken token2 = createToken("id2", StatusToken.Status.ACTIVE, now, later);

            assertThat(token1).isNotEqualTo(token2);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            StatusToken token = createToken("id", StatusToken.Status.ACTIVE, Instant.now(),
                    Instant.now().plusSeconds(3600));
            assertThat(token).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should have meaningful toString")
        void shouldHaveMeaningfulToString() {
            StatusToken token = createToken("test-id", StatusToken.Status.ACTIVE, Instant.now(),
                    Instant.now().plusSeconds(3600));
            String str = token.toString();

            assertThat(str).contains("test-id");
            assertThat(str).contains("ACTIVE");
        }
    }

    private StatusToken createToken(String agentId, StatusToken.Status status,
                                    Instant issuedAt, Instant expiresAt) {
        return new StatusToken(
            agentId,
            status,
            issuedAt,
            expiresAt,
            "ans://test",
            "agent.example.com",
            List.of(),
            List.of(),
            Map.of(),
            null,
            null,
            null,
            null
        );
    }
}
