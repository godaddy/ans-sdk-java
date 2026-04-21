package com.godaddy.ans.sdk.transparency.scitt;

import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CoseSign1ParserTest {

    @Nested
    @DisplayName("parse() tests")
    class ParseTests {

        @Test
        @DisplayName("Should reject null input")
        void shouldRejectNullInput() {
            assertThatThrownBy(() -> CoseSign1Parser.parse(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("coseBytes cannot be null");
        }

        @Test
        @DisplayName("Should reject empty input")
        void shouldRejectEmptyInput() {
            assertThatThrownBy(() -> CoseSign1Parser.parse(new byte[0]))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Failed to decode CBOR");
        }

        @Test
        @DisplayName("Should reject invalid CBOR")
        void shouldRejectInvalidCbor() {
            byte[] invalidCbor = {0x01, 0x02, 0x03};
            assertThatThrownBy(() -> CoseSign1Parser.parse(invalidCbor))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Failed to decode CBOR");
        }

        @Test
        @DisplayName("Should reject CBOR without COSE_Sign1 tag")
        void shouldRejectCborWithoutTag() {
            // Array without tag
            CBORObject array = CBORObject.NewArray();
            array.Add(new byte[0]);
            array.Add(CBORObject.NewMap());
            array.Add(new byte[0]);
            array.Add(new byte[64]);

            assertThatThrownBy(() -> CoseSign1Parser.parse(array.EncodeToBytes()))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Expected COSE_Sign1 tag (18)");
        }

        @Test
        @DisplayName("Should reject COSE_Sign1 with wrong number of elements")
        void shouldRejectWrongElementCount() {
            // Tag 18 but only 3 elements
            CBORObject array = CBORObject.NewArray();
            array.Add(new byte[0]);
            array.Add(CBORObject.NewMap());
            array.Add(new byte[0]);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            assertThatThrownBy(() -> CoseSign1Parser.parse(tagged.EncodeToBytes()))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("must be an array of 4 elements");
        }

        @Test
        @DisplayName("Should reject non-ES256 algorithm")
        void shouldRejectNonEs256Algorithm() throws Exception {
            // Build COSE_Sign1 with RS256 (alg = -257)
            CBORObject protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(1, -257);  // alg = RS256
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(CBORObject.NewMap());
            array.Add(new byte[0]);  // payload
            array.Add(new byte[64]);  // signature
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            assertThatThrownBy(() -> CoseSign1Parser.parse(tagged.EncodeToBytes()))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Algorithm substitution attack prevented")
                .hasMessageContaining("only ES256 (alg=-7) is accepted");
        }

        @Test
        @DisplayName("Should reject invalid signature length")
        void shouldRejectInvalidSignatureLength() throws Exception {
            // Build valid COSE_Sign1 with ES256 but wrong signature length
            CBORObject protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(1, -7);  // alg = ES256
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(CBORObject.NewMap());
            array.Add(new byte[0]);  // payload
            array.Add(new byte[32]);  // Wrong! Should be 64 bytes
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            assertThatThrownBy(() -> CoseSign1Parser.parse(tagged.EncodeToBytes()))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Invalid ES256 signature length")
                .hasMessageContaining("expected 64 bytes");
        }

        @Test
        @DisplayName("Should parse valid COSE_Sign1 with ES256")
        void shouldParseValidCoseSign1() throws Exception {
            // Build valid COSE_Sign1
            CBORObject protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(1, -7);  // alg = ES256
            protectedHeader.Add(4, new byte[]{0x01, 0x02, 0x03, 0x04});  // kid
            protectedHeader.Add(395, 1);  // vds = RFC9162_SHA256
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            byte[] payload = "test payload".getBytes(StandardCharsets.UTF_8);
            byte[] signature = new byte[64];  // 64-byte placeholder

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(CBORObject.NewMap());
            array.Add(payload);
            array.Add(signature);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            CoseSign1Parser.ParsedCoseSign1 parsed = CoseSign1Parser.parse(tagged.EncodeToBytes());

            assertThat(parsed.protectedHeader().algorithm()).isEqualTo(-7);
            assertThat(parsed.protectedHeader().keyId()).containsExactly(0x01, 0x02, 0x03, 0x04);
            assertThat(parsed.protectedHeader().vds()).isEqualTo(1);
            assertThat(parsed.payload()).isEqualTo(payload);
            assertThat(parsed.signature()).hasSize(64);
        }

        @Test
        @DisplayName("Should reject empty protected header bytes")
        void shouldRejectEmptyProtectedHeaderBytes() {
            // Build COSE_Sign1 with empty protected header
            CBORObject array = CBORObject.NewArray();
            array.Add(new byte[0]);  // Empty protected header
            array.Add(CBORObject.NewMap());
            array.Add(new byte[0]);
            array.Add(new byte[64]);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            assertThatThrownBy(() -> CoseSign1Parser.parse(tagged.EncodeToBytes()))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Protected header cannot be empty");
        }

        @Test
        @DisplayName("Should reject protected header that is not a CBOR map")
        void shouldRejectNonMapProtectedHeader() {
            // Protected header encoded as array instead of map
            CBORObject protectedArray = CBORObject.NewArray();
            protectedArray.Add(-7);
            byte[] protectedBytes = protectedArray.EncodeToBytes();

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(CBORObject.NewMap());
            array.Add(new byte[0]);
            array.Add(new byte[64]);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            assertThatThrownBy(() -> CoseSign1Parser.parse(tagged.EncodeToBytes()))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Protected header must be a CBOR map");
        }

        @Test
        @DisplayName("Should reject protected header missing algorithm")
        void shouldRejectMissingAlgorithm() {
            // Protected header without alg field
            CBORObject protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(4, new byte[]{0x01, 0x02, 0x03, 0x04});  // Only kid, no alg
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(CBORObject.NewMap());
            array.Add(new byte[0]);
            array.Add(new byte[64]);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            assertThatThrownBy(() -> CoseSign1Parser.parse(tagged.EncodeToBytes()))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Protected header missing algorithm");
        }

        @Test
        @DisplayName("Should parse COSE_Sign1 with detached (null) payload")
        void shouldParseDetachedPayload() throws Exception {
            CBORObject protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(1, -7);  // alg = ES256
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(CBORObject.NewMap());
            array.Add(CBORObject.Null);  // Null payload (detached)
            array.Add(new byte[64]);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            CoseSign1Parser.ParsedCoseSign1 parsed = CoseSign1Parser.parse(tagged.EncodeToBytes());

            assertThat(parsed.payload()).isNull();
        }

        @Test
        @DisplayName("Should reject non-byte-string protected header element")
        void shouldRejectNonByteStringProtectedHeader() {
            CBORObject array = CBORObject.NewArray();
            array.Add("not bytes");  // String instead of byte string
            array.Add(CBORObject.NewMap());
            array.Add(new byte[0]);
            array.Add(new byte[64]);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            assertThatThrownBy(() -> CoseSign1Parser.parse(tagged.EncodeToBytes()))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("must be a byte string");
        }

        @Test
        @DisplayName("Should parse protected header with integer content type")
        void shouldParseIntegerContentType() throws Exception {
            CBORObject protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(1, -7);  // alg = ES256
            protectedHeader.Add(3, 60);  // content type as integer (application/cbor)
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(CBORObject.NewMap());
            array.Add(new byte[0]);
            array.Add(new byte[64]);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            CoseSign1Parser.ParsedCoseSign1 parsed = CoseSign1Parser.parse(tagged.EncodeToBytes());

            assertThat(parsed.protectedHeader().contentType()).isEqualTo("60");
        }

        @Test
        @DisplayName("Should parse protected header with string content type")
        void shouldParseStringContentType() throws Exception {
            CBORObject protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(1, -7);  // alg = ES256
            protectedHeader.Add(3, "application/json");  // content type as string
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(CBORObject.NewMap());
            array.Add(new byte[0]);
            array.Add(new byte[64]);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            CoseSign1Parser.ParsedCoseSign1 parsed = CoseSign1Parser.parse(tagged.EncodeToBytes());

            assertThat(parsed.protectedHeader().contentType()).isEqualTo("application/json");
        }

        @Test
        @DisplayName("Should handle null unprotected header")
        void shouldHandleNullUnprotectedHeader() throws Exception {
            CBORObject protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(1, -7);
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(CBORObject.Null);  // Null unprotected header
            array.Add(new byte[0]);
            array.Add(new byte[64]);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            CoseSign1Parser.ParsedCoseSign1 parsed = CoseSign1Parser.parse(tagged.EncodeToBytes());

            assertThat(parsed.unprotectedHeader().isNull()).isTrue();
        }

        @Test
        @DisplayName("Should parse COSE_Sign1 with CWT claims")
        void shouldParseCwtClaims() throws Exception {
            // Build COSE_Sign1 with CWT claims in protected header
            CBORObject cwtClaims = CBORObject.NewMap();
            cwtClaims.Add(1, "issuer");  // iss
            cwtClaims.Add(2, "subject");  // sub
            cwtClaims.Add(4, 1700000000L);  // exp
            cwtClaims.Add(6, 1600000000L);  // iat

            CBORObject protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(1, -7);  // alg = ES256
            protectedHeader.Add(15, cwtClaims);  // cwt_claims
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(CBORObject.NewMap());
            array.Add(new byte[0]);
            array.Add(new byte[64]);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            CoseSign1Parser.ParsedCoseSign1 parsed = CoseSign1Parser.parse(tagged.EncodeToBytes());

            CwtClaims claims = parsed.protectedHeader().cwtClaims();
            assertThat(claims).isNotNull();
            assertThat(claims.iss()).isEqualTo("issuer");
            assertThat(claims.sub()).isEqualTo("subject");
            assertThat(claims.exp()).isEqualTo(1700000000L);
            assertThat(claims.iat()).isEqualTo(1600000000L);
        }
    }

    @Nested
    @DisplayName("buildSigStructure() tests")
    class BuildSigStructureTests {

        @Test
        @DisplayName("Should build correct Sig_structure")
        void shouldBuildCorrectSigStructure() {
            byte[] protectedHeader = new byte[]{0x01, 0x02};
            byte[] externalAad = new byte[]{0x03, 0x04};
            byte[] payload = "payload".getBytes();

            byte[] sigStructure = CoseSign1Parser.buildSigStructure(protectedHeader, externalAad, payload);

            // Decode and verify structure
            CBORObject decoded = CBORObject.DecodeFromBytes(sigStructure);
            assertThat(decoded.size()).isEqualTo(4);
            assertThat(decoded.get(0).AsString()).isEqualTo("Signature1");
            assertThat(decoded.get(1).GetByteString()).isEqualTo(protectedHeader);
            assertThat(decoded.get(2).GetByteString()).isEqualTo(externalAad);
            assertThat(decoded.get(3).GetByteString()).isEqualTo(payload);
        }

        @Test
        @DisplayName("Should handle null values")
        void shouldHandleNullValues() {
            byte[] sigStructure = CoseSign1Parser.buildSigStructure(null, null, null);

            CBORObject decoded = CBORObject.DecodeFromBytes(sigStructure);
            assertThat(decoded.get(1).GetByteString()).isEmpty();
            assertThat(decoded.get(2).GetByteString()).isEmpty();
            assertThat(decoded.get(3).GetByteString()).isEmpty();
        }
    }

    @Nested
    @DisplayName("CoseProtectedHeader tests")
    class CoseProtectedHeaderTests {

        @Test
        @DisplayName("Should detect RFC 9162 Merkle tree VDS")
        void shouldDetectRfc9162MerkleTree() {
            CoseProtectedHeader header = new CoseProtectedHeader(-7, null, 1, null, null);
            assertThat(header.isRfc9162MerkleTree()).isTrue();

            CoseProtectedHeader headerOther = new CoseProtectedHeader(-7, null, 2, null, null);
            assertThat(headerOther.isRfc9162MerkleTree()).isFalse();

            CoseProtectedHeader headerNull = new CoseProtectedHeader(-7, null, null, null, null);
            assertThat(headerNull.isRfc9162MerkleTree()).isFalse();
        }

        @Test
        @DisplayName("Should format key ID as hex")
        void shouldFormatKeyIdAsHex() {
            CoseProtectedHeader header = new CoseProtectedHeader(-7,
                new byte[]{(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF}, null, null, null);
            assertThat(header.keyIdHex()).isEqualTo("deadbeef");
        }
    }
}
