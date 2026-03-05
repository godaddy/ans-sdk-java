package com.godaddy.ans.sdk.agent.http;

import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.agent.verification.ConnectionVerifier;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link VerifiedClientResult}.
 */
class VerifiedClientResultTest {

    // ==================== Construction Tests ====================

    @Test
    @DisplayName("Should construct with valid parameters")
    void shouldConstructWithValidParameters() {
        // Given
        ConnectionVerifier verifier = NoOpConnectionVerifier.INSTANCE;
        AnsHttpClient ansHttpClient = createMockAnsHttpClient();

        // When
        VerifiedClientResult result = new VerifiedClientResult(verifier, ansHttpClient);

        // Then
        assertThat(result.verifier()).isEqualTo(verifier);
        assertThat(result.ansHttpClient()).isEqualTo(ansHttpClient);
    }

    @Test
    @DisplayName("Should access verifier component")
    void shouldAccessVerifierComponent() {
        // Given
        ConnectionVerifier verifier = NoOpConnectionVerifier.INSTANCE;
        AnsHttpClient ansHttpClient = createMockAnsHttpClient();

        // When
        VerifiedClientResult result = new VerifiedClientResult(verifier, ansHttpClient);

        // Then
        assertThat(result.verifier()).isSameAs(verifier);
    }

    @Test
    @DisplayName("Should access ansHttpClient component")
    void shouldAccessAnsHttpClientComponent() {
        // Given
        ConnectionVerifier verifier = NoOpConnectionVerifier.INSTANCE;
        AnsHttpClient ansHttpClient = createMockAnsHttpClient();

        // When
        VerifiedClientResult result = new VerifiedClientResult(verifier, ansHttpClient);

        // Then
        assertThat(result.ansHttpClient()).isSameAs(ansHttpClient);
    }

    // ==================== Null Validation Tests ====================

    @Test
    @DisplayName("Should reject null verifier")
    void shouldRejectNullVerifier() {
        // Given
        AnsHttpClient ansHttpClient = createMockAnsHttpClient();

        // When/Then
        assertThatThrownBy(() -> new VerifiedClientResult(null, ansHttpClient))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("ConnectionVerifier cannot be null");
    }

    @Test
    @DisplayName("Should reject null ansHttpClient")
    void shouldRejectNullAnsHttpClient() {
        // Given
        ConnectionVerifier verifier = NoOpConnectionVerifier.INSTANCE;

        // When/Then
        assertThatThrownBy(() -> new VerifiedClientResult(verifier, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("AnsHttpClient cannot be null");
    }

    @Test
    @DisplayName("Should reject both null parameters")
    void shouldRejectBothNullParameters() {
        // When/Then - should fail on first null check (verifier)
        assertThatThrownBy(() -> new VerifiedClientResult(null, null))
            .isInstanceOf(NullPointerException.class);
    }

    // ==================== Equality Tests ====================

    @Test
    @DisplayName("Records with same components should be equal")
    void recordsWithSameComponentsShouldBeEqual() {
        // Given
        ConnectionVerifier verifier = NoOpConnectionVerifier.INSTANCE;
        AnsHttpClient ansHttpClient = createMockAnsHttpClient();

        // When
        VerifiedClientResult result1 = new VerifiedClientResult(verifier, ansHttpClient);
        VerifiedClientResult result2 = new VerifiedClientResult(verifier, ansHttpClient);

        // Then
        assertThat(result1).isEqualTo(result2);
        assertThat(result1.hashCode()).isEqualTo(result2.hashCode());
    }

    @Test
    @DisplayName("Records with different verifiers should not be equal")
    void recordsWithDifferentVerifiersShouldNotBeEqual() {
        // Given
        ConnectionVerifier verifier1 = NoOpConnectionVerifier.INSTANCE;
        ConnectionVerifier verifier2 = mock(ConnectionVerifier.class);
        AnsHttpClient ansHttpClient = createMockAnsHttpClient();

        // When
        VerifiedClientResult result1 = new VerifiedClientResult(verifier1, ansHttpClient);
        VerifiedClientResult result2 = new VerifiedClientResult(verifier2, ansHttpClient);

        // Then
        assertThat(result1).isNotEqualTo(result2);
    }

    @Test
    @DisplayName("Records with different clients should not be equal")
    void recordsWithDifferentClientsShouldNotBeEqual() {
        // Given
        ConnectionVerifier verifier = NoOpConnectionVerifier.INSTANCE;
        AnsHttpClient ansHttpClient1 = createMockAnsHttpClient();
        AnsHttpClient ansHttpClient2 = createMockAnsHttpClient();

        // When
        VerifiedClientResult result1 = new VerifiedClientResult(verifier, ansHttpClient1);
        VerifiedClientResult result2 = new VerifiedClientResult(verifier, ansHttpClient2);

        // Then
        assertThat(result1).isNotEqualTo(result2);
    }

    @Test
    @DisplayName("Record should not be equal to null")
    void recordShouldNotBeEqualToNull() {
        // Given
        ConnectionVerifier verifier = NoOpConnectionVerifier.INSTANCE;
        AnsHttpClient ansHttpClient = createMockAnsHttpClient();
        VerifiedClientResult result = new VerifiedClientResult(verifier, ansHttpClient);

        // Then
        assertThat(result).isNotEqualTo(null);
    }

    @Test
    @DisplayName("Record should not be equal to different type")
    void recordShouldNotBeEqualToDifferentType() {
        // Given
        ConnectionVerifier verifier = NoOpConnectionVerifier.INSTANCE;
        AnsHttpClient ansHttpClient = createMockAnsHttpClient();
        VerifiedClientResult result = new VerifiedClientResult(verifier, ansHttpClient);

        // Then
        assertThat(result).isNotEqualTo("some string");
        assertThat(result).isNotEqualTo(123);
    }

    // ==================== toString Tests ====================

    @Test
    @DisplayName("toString should contain component info")
    void toStringShouldContainComponentInfo() {
        // Given
        ConnectionVerifier verifier = NoOpConnectionVerifier.INSTANCE;
        AnsHttpClient ansHttpClient = createMockAnsHttpClient();
        VerifiedClientResult result = new VerifiedClientResult(verifier, ansHttpClient);

        // When
        String str = result.toString();

        // Then
        assertThat(str).contains("VerifiedClientResult");
        assertThat(str).contains("verifier");
        assertThat(str).contains("ansHttpClient");
    }

    // ==================== Helper Methods ====================

    private AnsHttpClient createMockAnsHttpClient() {
        HttpClient mockDelegate = mock(HttpClient.class);
        return AnsHttpClient.builder()
            .delegate(mockDelegate)
            .connectionVerifier(NoOpConnectionVerifier.INSTANCE)
            .verificationPolicy(VerificationPolicy.PKI_ONLY)
            .build();
    }
}
