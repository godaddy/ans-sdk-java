package com.godaddy.ans.sdk.transparency.scitt;

import com.godaddy.ans.sdk.transparency.model.CertType;
import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class StatusTokenParserTest {

    // ---------------------------------------------------------------------------
    // Shared helper: builds a minimal valid COSE_Sign1 with the given payload bytes
    // ---------------------------------------------------------------------------

    private static byte[] buildCoseSign1(byte[] payloadBytes) {
        CBORObject protectedHeader = CBORObject.NewMap();
        protectedHeader.Add(1, -7);  // alg = ES256
        byte[] protectedBytes = protectedHeader.EncodeToBytes();

        CBORObject array = CBORObject.NewArray();
        array.Add(protectedBytes);
        array.Add(CBORObject.NewMap());
        array.Add(payloadBytes);
        array.Add(new byte[64]);  // 64-byte placeholder signature
        CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

        return tagged.EncodeToBytes();
    }

    /**
     * Builds a minimal valid {@link CoseSign1Parser.ParsedCoseSign1} wrapping the
     * supplied payload bytes.  The protected header uses ES256 and the signature is
     * a 64-byte zero array.
     */
    private static CoseSign1Parser.ParsedCoseSign1 buildParsedCose(byte[] payloadBytes) {
        CBORObject protectedHeaderMap = CBORObject.NewMap();
        protectedHeaderMap.Add(1, -7);  // alg = ES256
        byte[] protectedHeaderBytes = protectedHeaderMap.EncodeToBytes();

        CoseProtectedHeader header = new CoseProtectedHeader(-7, null, null, null, null);

        return new CoseSign1Parser.ParsedCoseSign1(
            protectedHeaderBytes,
            header,
            CBORObject.NewMap(),
            payloadBytes,
            new byte[64]
        );
    }

    // ---------------------------------------------------------------------------
    // parseStatus tests
    // ---------------------------------------------------------------------------

    @Nested
    @DisplayName("parseStatus() tests")
    class ParseStatusTests {

        @Test
        @DisplayName("Null input returns UNKNOWN")
        void nullReturnsUnknown() {
            assertThat(StatusTokenParser.parseStatus(null))
                .isEqualTo(StatusToken.Status.UNKNOWN);
        }

        @Test
        @DisplayName("'active' (lowercase) returns ACTIVE")
        void lowercaseActiveReturnsActive() {
            assertThat(StatusTokenParser.parseStatus("active"))
                .isEqualTo(StatusToken.Status.ACTIVE);
        }

        @Test
        @DisplayName("'Active' (mixed case) returns ACTIVE")
        void mixedCaseActiveReturnsActive() {
            assertThat(StatusTokenParser.parseStatus("Active"))
                .isEqualTo(StatusToken.Status.ACTIVE);
        }

        @Test
        @DisplayName("Unrecognized string returns UNKNOWN")
        void unrecognizedStringReturnsUnknown() {
            assertThat(StatusTokenParser.parseStatus("bogus"))
                .isEqualTo(StatusToken.Status.UNKNOWN);
        }

        @Test
        @DisplayName("Empty string returns UNKNOWN")
        void emptyStringReturnsUnknown() {
            assertThat(StatusTokenParser.parseStatus(""))
                .isEqualTo(StatusToken.Status.UNKNOWN);
        }

        @Test
        @DisplayName("All known status values are parsed correctly")
        void allKnownStatusValues() {
            assertThat(StatusTokenParser.parseStatus("ACTIVE"))
                .isEqualTo(StatusToken.Status.ACTIVE);
            assertThat(StatusTokenParser.parseStatus("WARNING"))
                .isEqualTo(StatusToken.Status.WARNING);
            assertThat(StatusTokenParser.parseStatus("DEPRECATED"))
                .isEqualTo(StatusToken.Status.DEPRECATED);
            assertThat(StatusTokenParser.parseStatus("EXPIRED"))
                .isEqualTo(StatusToken.Status.EXPIRED);
            assertThat(StatusTokenParser.parseStatus("REVOKED"))
                .isEqualTo(StatusToken.Status.REVOKED);
            assertThat(StatusTokenParser.parseStatus("UNKNOWN"))
                .isEqualTo(StatusToken.Status.UNKNOWN);
        }
    }

    // ---------------------------------------------------------------------------
    // extractRequiredString tests
    // ---------------------------------------------------------------------------

    @Nested
    @DisplayName("extractRequiredString() tests")
    class ExtractRequiredStringTests {

        @Test
        @DisplayName("Extracts existing string value")
        void extractsExistingStringValue() throws ScittParseException {
            CBORObject map = CBORObject.NewMap();
            map.Add(1, "hello");

            assertThat(StatusTokenParser.extractRequiredString(map, 1))
                .isEqualTo("hello");
        }

        @Test
        @DisplayName("Throws ScittParseException for missing key")
        void throwsForMissingKey() {
            CBORObject map = CBORObject.NewMap();

            assertThatThrownBy(() -> StatusTokenParser.extractRequiredString(map, 99))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Missing required field at key 99");
        }

        @Test
        @DisplayName("Throws ScittParseException for explicit CBOR null value")
        void throwsForNullValue() {
            CBORObject map = CBORObject.NewMap();
            map.set(CBORObject.FromObject(1), CBORObject.Null);

            assertThatThrownBy(() -> StatusTokenParser.extractRequiredString(map, 1))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Missing required field at key 1");
        }

        @Test
        @DisplayName("Throws ScittParseException for non-string value (integer)")
        void throwsForNonStringValue() {
            CBORObject map = CBORObject.NewMap();
            map.Add(1, 42);

            assertThatThrownBy(() -> StatusTokenParser.extractRequiredString(map, 1))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("must be a string");
        }
    }

    // ---------------------------------------------------------------------------
    // extractOptionalString tests
    // ---------------------------------------------------------------------------

    @Nested
    @DisplayName("extractOptionalString() tests")
    class ExtractOptionalStringTests {

        @Test
        @DisplayName("Returns string when key is present")
        void returnsStringWhenPresent() {
            CBORObject map = CBORObject.NewMap();
            map.Add(5, "ans.name");

            assertThat(StatusTokenParser.extractOptionalString(map, 5))
                .isEqualTo("ans.name");
        }

        @Test
        @DisplayName("Returns null when key is missing")
        void returnsNullWhenMissing() {
            CBORObject map = CBORObject.NewMap();

            assertThat(StatusTokenParser.extractOptionalString(map, 5))
                .isNull();
        }

        @Test
        @DisplayName("Returns null for non-string type (integer)")
        void returnsNullForNonStringType() {
            CBORObject map = CBORObject.NewMap();
            map.Add(5, 123);

            assertThat(StatusTokenParser.extractOptionalString(map, 5))
                .isNull();
        }

        @Test
        @DisplayName("Returns null for CBOR null value")
        void returnsNullForCborNull() {
            CBORObject map = CBORObject.NewMap();
            map.set(CBORObject.FromObject(5), CBORObject.Null);

            assertThat(StatusTokenParser.extractOptionalString(map, 5))
                .isNull();
        }
    }

    // ---------------------------------------------------------------------------
    // extractOptionalLong tests
    // ---------------------------------------------------------------------------

    @Nested
    @DisplayName("extractOptionalLong() tests")
    class ExtractOptionalLongTests {

        @Test
        @DisplayName("Returns long when key is present")
        void returnsLongWhenPresent() {
            CBORObject map = CBORObject.NewMap();
            long value = 1700000000L;
            map.Add(4, value);

            assertThat(StatusTokenParser.extractOptionalLong(map, 4))
                .isEqualTo(value);
        }

        @Test
        @DisplayName("Returns null when key is missing")
        void returnsNullWhenMissing() {
            CBORObject map = CBORObject.NewMap();

            assertThat(StatusTokenParser.extractOptionalLong(map, 4))
                .isNull();
        }

        @Test
        @DisplayName("Returns null for non-numeric type (string)")
        void returnsNullForNonNumericType() {
            CBORObject map = CBORObject.NewMap();
            map.Add(4, "not-a-number");

            assertThat(StatusTokenParser.extractOptionalLong(map, 4))
                .isNull();
        }

        @Test
        @DisplayName("Returns null for CBOR null value")
        void returnsNullForCborNull() {
            CBORObject map = CBORObject.NewMap();
            map.set(CBORObject.FromObject(4), CBORObject.Null);

            assertThat(StatusTokenParser.extractOptionalLong(map, 4))
                .isNull();
        }
    }

    // ---------------------------------------------------------------------------
    // extractCertificateList tests
    // ---------------------------------------------------------------------------

    @Nested
    @DisplayName("extractCertificateList() tests")
    class ExtractCertificateListTests {

        @Test
        @DisplayName("Returns empty list when key is missing")
        void returnsEmptyForMissingKey() {
            CBORObject map = CBORObject.NewMap();

            assertThat(StatusTokenParser.extractCertificateList(map, 6))
                .isEmpty();
        }

        @Test
        @DisplayName("Returns empty list when value is not an array")
        void returnsEmptyForNonArrayValue() {
            CBORObject map = CBORObject.NewMap();
            map.Add(6, "not-an-array");

            assertThat(StatusTokenParser.extractCertificateList(map, 6))
                .isEmpty();
        }

        @Test
        @DisplayName("Parses map-format certificates with fingerprint and type")
        void parsesMapCertificatesWithFingerprintAndType() {
            CBORObject map = CBORObject.NewMap();

            CBORObject certMap = CBORObject.NewMap();
            certMap.Add(1, "SHA256:abc123");           // fingerprint
            certMap.Add(2, "X509-DV-SERVER");          // type

            CBORObject array = CBORObject.NewArray();
            array.Add(certMap);
            map.Add(6, array);

            var certs = StatusTokenParser.extractCertificateList(map, 6);

            assertThat(certs).hasSize(1);
            assertThat(certs.get(0).getFingerprint()).isEqualTo("SHA256:abc123");
            assertThat(certs.get(0).getType()).isEqualTo(CertType.X509_DV_SERVER);
        }

        @Test
        @DisplayName("Parses string-format certificates")
        void parsesStringCertificates() {
            CBORObject map = CBORObject.NewMap();

            CBORObject array = CBORObject.NewArray();
            array.Add("SHA256:def456");

            map.Add(7, array);

            var certs = StatusTokenParser.extractCertificateList(map, 7);

            assertThat(certs).hasSize(1);
            assertThat(certs.get(0).getFingerprint()).isEqualTo("SHA256:def456");
            assertThat(certs.get(0).getType()).isNull();
        }

        @Test
        @DisplayName("Skips map certificates missing fingerprint key")
        void skipsMapCertificatesMissingFingerprint() {
            CBORObject map = CBORObject.NewMap();

            CBORObject certMapNoFingerprint = CBORObject.NewMap();
            certMapNoFingerprint.Add(2, "X509-DV-SERVER");  // type only, no fingerprint

            CBORObject array = CBORObject.NewArray();
            array.Add(certMapNoFingerprint);
            map.Add(6, array);

            var certs = StatusTokenParser.extractCertificateList(map, 6);

            assertThat(certs).isEmpty();
        }

        @Test
        @DisplayName("Handles mixed formats: maps and strings in same array")
        void handlesMixedFormats() {
            CBORObject map = CBORObject.NewMap();

            CBORObject certMap = CBORObject.NewMap();
            certMap.Add(1, "SHA256:fp-map");
            certMap.Add(2, "X509-EV-CLIENT");

            CBORObject array = CBORObject.NewArray();
            array.Add(certMap);
            array.Add("SHA256:fp-string");
            map.Add(6, array);

            var certs = StatusTokenParser.extractCertificateList(map, 6);

            assertThat(certs).hasSize(2);
            assertThat(certs.get(0).getFingerprint()).isEqualTo("SHA256:fp-map");
            assertThat(certs.get(0).getType()).isEqualTo(CertType.X509_EV_CLIENT);
            assertThat(certs.get(1).getFingerprint()).isEqualTo("SHA256:fp-string");
            assertThat(certs.get(1).getType()).isNull();
        }

        @Test
        @DisplayName("Parses map certificate with unknown type as null type")
        void parsesMapCertificateWithUnknownTypeAsNullType() {
            CBORObject map = CBORObject.NewMap();

            CBORObject certMap = CBORObject.NewMap();
            certMap.Add(1, "SHA256:fp-unknown");
            certMap.Add(2, "NOT-A-REAL-CERT-TYPE");

            CBORObject array = CBORObject.NewArray();
            array.Add(certMap);
            map.Add(6, array);

            var certs = StatusTokenParser.extractCertificateList(map, 6);

            assertThat(certs).hasSize(1);
            assertThat(certs.get(0).getFingerprint()).isEqualTo("SHA256:fp-unknown");
            assertThat(certs.get(0).getType()).isNull();
        }
    }

    // ---------------------------------------------------------------------------
    // extractMetadataHashes tests
    // ---------------------------------------------------------------------------

    @Nested
    @DisplayName("extractMetadataHashes() tests")
    class ExtractMetadataHashesTests {

        @Test
        @DisplayName("Returns empty map when key is missing")
        void returnsEmptyForMissingKey() {
            CBORObject map = CBORObject.NewMap();

            assertThat(StatusTokenParser.extractMetadataHashes(map, 8))
                .isEmpty();
        }

        @Test
        @DisplayName("Returns empty map when value is not a CBOR map")
        void returnsEmptyForNonMapValue() {
            CBORObject map = CBORObject.NewMap();
            map.Add(8, CBORObject.NewArray());

            assertThat(StatusTokenParser.extractMetadataHashes(map, 8))
                .isEmpty();
        }

        @Test
        @DisplayName("Extracts string key-value pairs")
        void extractsStringKeyValuePairs() {
            CBORObject map = CBORObject.NewMap();

            CBORObject hashes = CBORObject.NewMap();
            hashes.Add("a2a", "SHA256:hash1");
            hashes.Add("mcp", "SHA256:hash2");
            map.Add(8, hashes);

            Map<String, String> result = StatusTokenParser.extractMetadataHashes(map, 8);

            assertThat(result)
                .hasSize(2)
                .containsEntry("a2a", "SHA256:hash1")
                .containsEntry("mcp", "SHA256:hash2");
        }

        @Test
        @DisplayName("Skips entries with non-string keys (integer keys)")
        void skipsNonStringKeys() {
            CBORObject map = CBORObject.NewMap();

            CBORObject hashes = CBORObject.NewMap();
            hashes.Add("valid-key", "SHA256:hashA");
            hashes.Add(42, "SHA256:hashB");  // integer key — should be skipped
            map.Add(8, hashes);

            Map<String, String> result = StatusTokenParser.extractMetadataHashes(map, 8);

            assertThat(result)
                .hasSize(1)
                .containsEntry("valid-key", "SHA256:hashA");
        }

        @Test
        @DisplayName("Skips entries with non-string values (integer values)")
        void skipsNonStringValues() {
            CBORObject map = CBORObject.NewMap();

            CBORObject hashes = CBORObject.NewMap();
            hashes.Add("valid-key", "SHA256:hashA");
            hashes.Add("int-value", 999);  // integer value — should be skipped
            map.Add(8, hashes);

            Map<String, String> result = StatusTokenParser.extractMetadataHashes(map, 8);

            assertThat(result)
                .hasSize(1)
                .containsEntry("valid-key", "SHA256:hashA");
        }
    }

    // ---------------------------------------------------------------------------
    // fromParsedCose tests
    // ---------------------------------------------------------------------------

    @Nested
    @DisplayName("fromParsedCose() tests")
    class FromParsedCoseTests {

        @Test
        @DisplayName("Null input throws NullPointerException")
        void nullInputThrowsNpe() {
            assertThatThrownBy(() -> StatusTokenParser.fromParsedCose(null))
                .isInstanceOf(NullPointerException.class);
        }

        @Test
        @DisplayName("Empty payload throws ScittParseException")
        void emptyPayloadThrowsException() {
            CoseSign1Parser.ParsedCoseSign1 parsed = buildParsedCose(new byte[0]);

            assertThatThrownBy(() -> StatusTokenParser.fromParsedCose(parsed))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("payload cannot be empty");
        }

        @Test
        @DisplayName("Null payload throws ScittParseException")
        void nullPayloadThrowsException() {
            CoseSign1Parser.ParsedCoseSign1 parsed = buildParsedCose(null);

            assertThatThrownBy(() -> StatusTokenParser.fromParsedCose(parsed))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("payload cannot be empty");
        }

        @Test
        @DisplayName("Non-map payload throws ScittParseException")
        void nonMapPayloadThrowsException() {
            CBORObject array = CBORObject.NewArray();
            array.Add("not-a-map");
            CoseSign1Parser.ParsedCoseSign1 parsed = buildParsedCose(array.EncodeToBytes());

            assertThatThrownBy(() -> StatusTokenParser.fromParsedCose(parsed))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("must be a CBOR map");
        }

        @Test
        @DisplayName("Missing agent_id field throws ScittParseException")
        void missingAgentIdThrowsException() {
            CBORObject payload = CBORObject.NewMap();
            payload.Add(2, "ACTIVE");  // status present, agent_id missing
            long future = Instant.now().plusSeconds(3600).getEpochSecond();
            payload.Add(4, future);

            CoseSign1Parser.ParsedCoseSign1 parsed = buildParsedCose(payload.EncodeToBytes());

            assertThatThrownBy(() -> StatusTokenParser.fromParsedCose(parsed))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Missing required field");
        }

        @Test
        @DisplayName("Missing status field throws ScittParseException")
        void missingStatusThrowsException() {
            CBORObject payload = CBORObject.NewMap();
            payload.Add(1, "agent-id-only");  // agent_id present, status missing
            long future = Instant.now().plusSeconds(3600).getEpochSecond();
            payload.Add(4, future);

            CoseSign1Parser.ParsedCoseSign1 parsed = buildParsedCose(payload.EncodeToBytes());

            assertThatThrownBy(() -> StatusTokenParser.fromParsedCose(parsed))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Missing required field");
        }

        @Test
        @DisplayName("Missing exp field throws ScittParseException")
        void missingExpThrowsException() {
            CBORObject payload = CBORObject.NewMap();
            payload.Add(1, "test-agent");
            payload.Add(2, "ACTIVE");
            // No exp — must be rejected

            CoseSign1Parser.ParsedCoseSign1 parsed = buildParsedCose(payload.EncodeToBytes());

            assertThatThrownBy(() -> StatusTokenParser.fromParsedCose(parsed))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("missing required expiration time");
        }

        @Test
        @DisplayName("Valid minimal payload produces correct StatusToken")
        void validMinimalPayloadProducesStatusToken() throws ScittParseException {
            long expSeconds = Instant.now().plusSeconds(3600).getEpochSecond();

            CBORObject payload = CBORObject.NewMap();
            payload.Add(1, "test-agent-id");
            payload.Add(2, "active");          // lower-case — parser must upper-case it
            payload.Add(4, expSeconds);

            CoseSign1Parser.ParsedCoseSign1 parsed = buildParsedCose(payload.EncodeToBytes());

            StatusToken token = StatusTokenParser.fromParsedCose(parsed);

            assertThat(token.agentId()).isEqualTo("test-agent-id");
            assertThat(token.status()).isEqualTo(StatusToken.Status.ACTIVE);
            assertThat(token.expiresAt()).isEqualTo(Instant.ofEpochSecond(expSeconds));
            assertThat(token.issuedAt()).isNull();
            assertThat(token.ansName()).isNull();
            assertThat(token.validIdentityCerts()).isEmpty();
            assertThat(token.validServerCerts()).isEmpty();
            assertThat(token.metadataHashes()).isEmpty();
            assertThat(token.coseEnvelope()).isNotNull();
        }

        @Test
        @DisplayName("Payload iat and exp fields override absent CWT claims in header")
        void payloadTimestampsOverrideAbsentHeaderClaims() throws ScittParseException {
            long iatSeconds = Instant.now().getEpochSecond();
            long expSeconds = iatSeconds + 7200;

            CBORObject payload = CBORObject.NewMap();
            payload.Add(1, "agent-timestamps");
            payload.Add(2, "WARNING");
            payload.Add(3, iatSeconds);  // iat
            payload.Add(4, expSeconds);  // exp

            CoseSign1Parser.ParsedCoseSign1 parsed = buildParsedCose(payload.EncodeToBytes());

            StatusToken token = StatusTokenParser.fromParsedCose(parsed);

            assertThat(token.issuedAt()).isEqualTo(Instant.ofEpochSecond(iatSeconds));
            assertThat(token.expiresAt()).isEqualTo(Instant.ofEpochSecond(expSeconds));
            assertThat(token.status()).isEqualTo(StatusToken.Status.WARNING);
        }

        @Test
        @DisplayName("CWT claims in protected header supply timestamps when payload lacks them")
        void cwtClaimsSupplyTimestampsWhenPayloadLacksThem() throws ScittParseException {
            long expSeconds = Instant.now().plusSeconds(3600).getEpochSecond();
            long iatSeconds = Instant.now().getEpochSecond();

            // Protected header contains CWT claims
            CBORObject cwtMap = CBORObject.NewMap();
            cwtMap.Add(6, iatSeconds);    // iat (CWT label)
            cwtMap.Add(4, expSeconds);    // exp (CWT label)

            CBORObject protectedHeaderMap = CBORObject.NewMap();
            protectedHeaderMap.Add(1, -7);     // alg = ES256
            protectedHeaderMap.Add(13, cwtMap); // cwt_claims label
            byte[] protectedHeaderBytes = protectedHeaderMap.EncodeToBytes();

            CwtClaims cwtClaims = new CwtClaims(null, null, null, expSeconds, null, iatSeconds);
            CoseProtectedHeader header = new CoseProtectedHeader(-7, null, null, cwtClaims, null);

            // Payload has no iat/exp — should fall back to header claims
            CBORObject payload = CBORObject.NewMap();
            payload.Add(1, "agent-cwt");
            payload.Add(2, "ACTIVE");
            // No iat (key 3) and no exp (key 4) in payload

            CoseSign1Parser.ParsedCoseSign1 parsed = new CoseSign1Parser.ParsedCoseSign1(
                protectedHeaderBytes,
                header,
                CBORObject.NewMap(),
                payload.EncodeToBytes(),
                new byte[64]
            );

            StatusToken token = StatusTokenParser.fromParsedCose(parsed);

            assertThat(token.issuedAt()).isEqualTo(Instant.ofEpochSecond(iatSeconds));
            assertThat(token.expiresAt()).isEqualTo(Instant.ofEpochSecond(expSeconds));
        }

        @Test
        @DisplayName("Payload exp overrides CWT claims exp from protected header")
        void payloadExpOverridesCwtClaimsExp() throws ScittParseException {
            long cwtExpSeconds = Instant.now().plusSeconds(1800).getEpochSecond();
            long payloadExpSeconds = Instant.now().plusSeconds(7200).getEpochSecond();

            CwtClaims cwtClaims = new CwtClaims(null, null, null, cwtExpSeconds, null, null);
            CoseProtectedHeader header = new CoseProtectedHeader(-7, null, null, cwtClaims, null);

            CBORObject protectedHeaderMap = CBORObject.NewMap();
            protectedHeaderMap.Add(1, -7);
            byte[] protectedHeaderBytes = protectedHeaderMap.EncodeToBytes();

            CBORObject payload = CBORObject.NewMap();
            payload.Add(1, "agent-override");
            payload.Add(2, "ACTIVE");
            payload.Add(4, payloadExpSeconds);  // payload exp overrides header CWT exp

            CoseSign1Parser.ParsedCoseSign1 parsed = new CoseSign1Parser.ParsedCoseSign1(
                protectedHeaderBytes,
                header,
                CBORObject.NewMap(),
                payload.EncodeToBytes(),
                new byte[64]
            );

            StatusToken token = StatusTokenParser.fromParsedCose(parsed);

            assertThat(token.expiresAt()).isEqualTo(Instant.ofEpochSecond(payloadExpSeconds));
        }

        @Test
        @DisplayName("Valid full payload with all optional fields produces correct StatusToken")
        void validFullPayloadProducesStatusToken() throws ScittParseException {
            long iatSeconds = Instant.now().getEpochSecond();
            long expSeconds = iatSeconds + 3600;

            // Server cert as map
            CBORObject serverCertMap = CBORObject.NewMap();
            serverCertMap.Add(1, "SHA256:server-fp");
            serverCertMap.Add(2, "X509-DV-SERVER");

            CBORObject serverCerts = CBORObject.NewArray();
            serverCerts.Add(serverCertMap);

            // Identity cert as string
            CBORObject identityCerts = CBORObject.NewArray();
            identityCerts.Add("SHA256:identity-fp");

            // Metadata hashes
            CBORObject metadataHashes = CBORObject.NewMap();
            metadataHashes.Add("a2a", "SHA256:meta1");
            metadataHashes.Add("mcp", "SHA256:meta2");

            CBORObject payload = CBORObject.NewMap();
            payload.Add(1, "full-agent-id");
            payload.Add(2, "REVOKED");
            payload.Add(3, iatSeconds);
            payload.Add(4, expSeconds);
            payload.Add(5, "full.agent.ans");
            payload.Add(6, identityCerts);
            payload.Add(7, serverCerts);
            payload.Add(8, metadataHashes);

            CoseSign1Parser.ParsedCoseSign1 parsed = buildParsedCose(payload.EncodeToBytes());

            StatusToken token = StatusTokenParser.fromParsedCose(parsed);

            assertThat(token.agentId()).isEqualTo("full-agent-id");
            assertThat(token.status()).isEqualTo(StatusToken.Status.REVOKED);
            assertThat(token.issuedAt()).isEqualTo(Instant.ofEpochSecond(iatSeconds));
            assertThat(token.expiresAt()).isEqualTo(Instant.ofEpochSecond(expSeconds));
            assertThat(token.ansName()).isEqualTo("full.agent.ans");
            assertThat(token.validIdentityCerts()).hasSize(1);
            assertThat(token.validIdentityCerts().get(0).getFingerprint()).isEqualTo("SHA256:identity-fp");
            assertThat(token.validServerCerts()).hasSize(1);
            assertThat(token.validServerCerts().get(0).getFingerprint()).isEqualTo("SHA256:server-fp");
            assertThat(token.validServerCerts().get(0).getType()).isEqualTo(CertType.X509_DV_SERVER);
            assertThat(token.metadataHashes())
                .containsEntry("a2a", "SHA256:meta1")
                .containsEntry("mcp", "SHA256:meta2");
            assertThat(token.coseEnvelope()).isNotNull();
        }

        @Test
        @DisplayName("StatusToken has accessible coseEnvelope with correct payload bytes")
        void statusTokenHasAccessibleCoseEnvelope() throws ScittParseException {
            long expSeconds = Instant.now().plusSeconds(3600).getEpochSecond();

            CBORObject payload = CBORObject.NewMap();
            payload.Add(1, "envelope-agent");
            payload.Add(2, "ACTIVE");
            payload.Add(4, expSeconds);
            byte[] payloadBytes = payload.EncodeToBytes();

            CoseSign1Parser.ParsedCoseSign1 parsed = buildParsedCose(payloadBytes);

            StatusToken token = StatusTokenParser.fromParsedCose(parsed);

            assertThat(token.coseEnvelope()).isNotNull();
            assertThat(token.coseEnvelope().payload()).isEqualTo(payloadBytes);
            assertThat(token.coseEnvelope().signature()).hasSize(64);
            assertThat(token.coseEnvelope().protectedHeader()).isNotNull();
            assertThat(token.coseEnvelope().protectedHeader().algorithm()).isEqualTo(-7);
        }
    }

    // ---------------------------------------------------------------------------
    // parse(byte[]) integration-style tests (via the public static entry point)
    // ---------------------------------------------------------------------------

    @Nested
    @DisplayName("parse(byte[]) integration tests")
    class ParseBytesTests {

        @Test
        @DisplayName("Null coseBytes throws NullPointerException")
        void nullCoseBytesThrowsNpe() {
            assertThatThrownBy(() -> StatusTokenParser.parse(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("coseBytes cannot be null");
        }

        @Test
        @DisplayName("Valid COSE_Sign1 bytes produce a correct StatusToken")
        void validCoseBytesProduceStatusToken() throws ScittParseException {
            long expSeconds = Instant.now().plusSeconds(3600).getEpochSecond();

            CBORObject payload = CBORObject.NewMap();
            payload.Add(1, "parse-bytes-agent");
            payload.Add(2, "DEPRECATED");
            payload.Add(4, expSeconds);

            byte[] coseBytes = buildCoseSign1(payload.EncodeToBytes());

            StatusToken token = StatusTokenParser.parse(coseBytes);

            assertThat(token.agentId()).isEqualTo("parse-bytes-agent");
            assertThat(token.status()).isEqualTo(StatusToken.Status.DEPRECATED);
            assertThat(token.expiresAt()).isEqualTo(Instant.ofEpochSecond(expSeconds));
        }

        @Test
        @DisplayName("Invalid CBOR bytes throw ScittParseException")
        void invalidCborThrowsException() {
            byte[] garbage = {0x01, 0x02, 0x03};

            assertThatThrownBy(() -> StatusTokenParser.parse(garbage))
                .isInstanceOf(ScittParseException.class);
        }
    }
}
