package com.godaddy.ans.sdk.auth;

import com.godaddy.ans.sdk.exception.AnsAuthenticationException;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for RefreshableJwtCredentialsProvider.
 */
class RefreshableJwtCredentialsProviderTest {

    @Test
    void constructorShouldRejectNullSupplier() {
        assertThatThrownBy(() -> new RefreshableJwtCredentialsProvider(null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("null");
    }

    @Test
    void resolveCredentialsShouldReturnJwtCredentials() {
        RefreshableJwtCredentialsProvider provider = new RefreshableJwtCredentialsProvider(
            () -> "test-jwt-token"
        );

        AnsCredentials credentials = provider.resolveCredentials();

        assertThat(credentials).isNotNull();
        assertThat(credentials.getType()).isEqualTo(AnsCredentials.CredentialType.JWT);
        assertThat(credentials.getToken()).isEqualTo("test-jwt-token");
    }

    @Test
    void resolveCredentialsShouldCallSupplierEachTime() {
        AtomicInteger callCount = new AtomicInteger(0);
        RefreshableJwtCredentialsProvider provider = new RefreshableJwtCredentialsProvider(
            () -> "token-" + callCount.incrementAndGet()
        );

        AnsCredentials first = provider.resolveCredentials();
        AnsCredentials second = provider.resolveCredentials();

        assertThat(first.getToken()).isEqualTo("token-1");
        assertThat(second.getToken()).isEqualTo("token-2");
        assertThat(callCount.get()).isEqualTo(2);
    }

    @Test
    void resolveCredentialsShouldThrowWhenSupplierReturnsNull() {
        RefreshableJwtCredentialsProvider provider = new RefreshableJwtCredentialsProvider(
            () -> null
        );

        assertThatThrownBy(provider::resolveCredentials)
            .isInstanceOf(AnsAuthenticationException.class)
            .hasMessageContaining("null or blank");
    }

    @Test
    void resolveCredentialsShouldThrowWhenSupplierReturnsBlank() {
        RefreshableJwtCredentialsProvider provider = new RefreshableJwtCredentialsProvider(
            () -> "   "
        );

        assertThatThrownBy(provider::resolveCredentials)
            .isInstanceOf(AnsAuthenticationException.class)
            .hasMessageContaining("null or blank");
    }

    @Test
    void resolveCredentialsShouldWrapSupplierException() {
        RefreshableJwtCredentialsProvider provider = new RefreshableJwtCredentialsProvider(
            () -> {
                throw new RuntimeException("Token fetch failed");
            }
        );

        assertThatThrownBy(provider::resolveCredentials)
            .isInstanceOf(AnsAuthenticationException.class)
            .hasMessageContaining("Failed to obtain JWT token")
            .hasCauseInstanceOf(RuntimeException.class);
    }

    @Test
    void resolveCredentialsShouldRethrowAnsAuthenticationException() {
        AnsAuthenticationException originalException = new AnsAuthenticationException("Original error");
        RefreshableJwtCredentialsProvider provider = new RefreshableJwtCredentialsProvider(
            () -> {
                throw originalException;
            }
        );

        assertThatThrownBy(provider::resolveCredentials)
            .isSameAs(originalException);
    }
}
