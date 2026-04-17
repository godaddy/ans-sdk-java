package com.godaddy.ans.sdk.agent.verification;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DanePolicyTest {

    @Test
    @DisplayName("DISABLED.shouldVerify() returns false")
    void disabledShouldVerifyReturnsFalse() {
        assertThat(DanePolicy.DISABLED.shouldVerify()).isFalse();
    }

    @Test
    @DisplayName("DISABLED.isRequired() returns false")
    void disabledIsRequiredReturnsFalse() {
        assertThat(DanePolicy.DISABLED.isRequired()).isFalse();
    }

    @Test
    @DisplayName("VALIDATE_IF_PRESENT.shouldVerify() returns true")
    void validateIfPresentShouldVerifyReturnsTrue() {
        assertThat(DanePolicy.VALIDATE_IF_PRESENT.shouldVerify()).isTrue();
    }

    @Test
    @DisplayName("VALIDATE_IF_PRESENT.isRequired() returns false")
    void validateIfPresentIsRequiredReturnsFalse() {
        assertThat(DanePolicy.VALIDATE_IF_PRESENT.isRequired()).isFalse();
    }

    @Test
    @DisplayName("REQUIRED.shouldVerify() returns true")
    void requiredShouldVerifyReturnsTrue() {
        assertThat(DanePolicy.REQUIRED.shouldVerify()).isTrue();
    }

    @Test
    @DisplayName("REQUIRED.isRequired() returns true")
    void requiredIsRequiredReturnsTrue() {
        assertThat(DanePolicy.REQUIRED.isRequired()).isTrue();
    }

    @Test
    @DisplayName("All values are present")
    void allValuesPresent() {
        assertThat(DanePolicy.values()).hasSize(3);
        assertThat(DanePolicy.values()).containsExactly(
            DanePolicy.DISABLED,
            DanePolicy.VALIDATE_IF_PRESENT,
            DanePolicy.REQUIRED
        );
    }

    @Test
    @DisplayName("valueOf works correctly")
    void valueOfWorksCorrectly() {
        assertThat(DanePolicy.valueOf("DISABLED")).isEqualTo(DanePolicy.DISABLED);
        assertThat(DanePolicy.valueOf("VALIDATE_IF_PRESENT")).isEqualTo(DanePolicy.VALIDATE_IF_PRESENT);
        assertThat(DanePolicy.valueOf("REQUIRED")).isEqualTo(DanePolicy.REQUIRED);
    }
}
