package com.godaddy.ans.sdk.agent.verification;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DnssecValidationModeTest {

    @Test
    @DisplayName("TRUST_RESOLVER.isInCodeValidation() returns false")
    void trustResolverIsInCodeValidationReturnsFalse() {
        assertThat(DnssecValidationMode.TRUST_RESOLVER.isInCodeValidation()).isFalse();
    }

    @Test
    @DisplayName("TRUST_RESOLVER.requiresDnssecResolver() returns true")
    void trustResolverRequiresDnssecResolverReturnsTrue() {
        assertThat(DnssecValidationMode.TRUST_RESOLVER.requiresDnssecResolver()).isTrue();
    }

    @Test
    @DisplayName("VALIDATE_IN_CODE.isInCodeValidation() returns true")
    void validateInCodeIsInCodeValidationReturnsTrue() {
        assertThat(DnssecValidationMode.VALIDATE_IN_CODE.isInCodeValidation()).isTrue();
    }

    @Test
    @DisplayName("VALIDATE_IN_CODE.requiresDnssecResolver() returns false")
    void validateInCodeRequiresDnssecResolverReturnsFalse() {
        assertThat(DnssecValidationMode.VALIDATE_IN_CODE.requiresDnssecResolver()).isFalse();
    }

    @Test
    @DisplayName("All values are present")
    void allValuesPresent() {
        assertThat(DnssecValidationMode.values()).hasSize(2);
        assertThat(DnssecValidationMode.values()).containsExactly(
            DnssecValidationMode.TRUST_RESOLVER,
            DnssecValidationMode.VALIDATE_IN_CODE
        );
    }

    @Test
    @DisplayName("valueOf works correctly")
    void valueOfWorksCorrectly() {
        assertThat(DnssecValidationMode.valueOf("TRUST_RESOLVER")).isEqualTo(DnssecValidationMode.TRUST_RESOLVER);
        assertThat(DnssecValidationMode.valueOf("VALIDATE_IN_CODE")).isEqualTo(DnssecValidationMode.VALIDATE_IN_CODE);
    }
}
