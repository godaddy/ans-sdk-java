package com.godaddy.ans.sdk.transparency.scitt;

import java.time.Instant;

/**
 * CWT (CBOR Web Token) claims as defined in RFC 8392.
 *
 * <p>These claims are embedded in SCITT status tokens to provide
 * time-bounded assertions about agent status.</p>
 *
 * @param iss issuer - identifies the principal that issued the token
 * @param sub subject - identifies the principal that is the subject
 * @param aud audience - identifies the recipients the token is intended for
 * @param exp expiration time - time after which the token must not be accepted (seconds since epoch)
 * @param nbf not before - time before which the token must not be accepted (seconds since epoch)
 * @param iat issued at - time at which the token was issued (seconds since epoch)
 */
public record CwtClaims(
    String iss,
    String sub,
    String aud,
    Long exp,
    Long nbf,
    Long iat
) {

    /**
     * Returns the expiration time as an Instant.
     *
     * @return the expiration time, or null if not set
     */
    public Instant expirationTime() {
        return exp != null ? Instant.ofEpochSecond(exp) : null;
    }

    /**
     * Returns the not-before time as an Instant.
     *
     * @return the not-before time, or null if not set
     */
    public Instant notBeforeTime() {
        return nbf != null ? Instant.ofEpochSecond(nbf) : null;
    }

    /**
     * Returns the issued-at time as an Instant.
     *
     * @return the issued-at time, or null if not set
     */
    public Instant issuedAtTime() {
        return iat != null ? Instant.ofEpochSecond(iat) : null;
    }
}
