package com.godaddy.ans.sdk.auth;

import com.godaddy.ans.sdk.exception.AnsAuthenticationException;

import java.util.function.Supplier;

/**
 * Credentials provider that uses a supplier to obtain JWT tokens.
 *
 * <p>This provider calls the supplier each time credentials are resolved,
 * allowing for token refresh logic to be implemented externally.</p>
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * AnsCredentialsProvider provider = new RefreshableJwtCredentialsProvider(
 *     () -> fetchNewJwtToken()  // Your token fetch logic
 * );
 * }</pre>
 */
public final class RefreshableJwtCredentialsProvider implements AnsCredentialsProvider {

    private final Supplier<String> tokenSupplier;

    /**
     * Creates a provider with the specified token supplier.
     *
     * @param tokenSupplier a supplier that returns a fresh JWT token
     * @throws IllegalArgumentException if the supplier is null
     */
    public RefreshableJwtCredentialsProvider(Supplier<String> tokenSupplier) {
        if (tokenSupplier == null) {
            throw new IllegalArgumentException("Token supplier cannot be null");
        }
        this.tokenSupplier = tokenSupplier;
    }

    @Override
    public AnsCredentials resolveCredentials() {
        try {
            String token = tokenSupplier.get();
            if (token == null || token.isBlank()) {
                throw new AnsAuthenticationException("Token supplier returned null or blank token");
            }
            return AnsCredentials.ofJwt(token);
        } catch (AnsAuthenticationException e) {
            throw e;
        } catch (Exception e) {
            throw new AnsAuthenticationException("Failed to obtain JWT token: " + e.getMessage(), e);
        }
    }
}