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

    /**
     * Checks if the token is expired at the given time.
     *
     * @param now the current time
     * @return true if the token is expired
     */
    public boolean isExpired(Instant now) {
        if (exp == null) {
            return false;  // No expiration set
        }
        return now.isAfter(expirationTime());
    }

    /**
     * Checks if the token is expired at the given time with clock skew tolerance.
     *
     * @param now the current time
     * @param clockSkewSeconds allowed clock skew in seconds
     * @return true if the token is expired (accounting for clock skew)
     */
    public boolean isExpired(Instant now, long clockSkewSeconds) {
        if (exp == null) {
            return false;
        }
        return now.minusSeconds(clockSkewSeconds).isAfter(expirationTime());
    }

    /**
     * Checks if the token is not yet valid at the given time.
     *
     * @param now the current time
     * @return true if the token is not yet valid
     */
    public boolean isNotYetValid(Instant now) {
        if (nbf == null) {
            return false;  // No not-before set
        }
        return now.isBefore(notBeforeTime());
    }

    /**
     * Checks if the token is not yet valid at the given time with clock skew tolerance.
     *
     * @param now the current time
     * @param clockSkewSeconds allowed clock skew in seconds
     * @return true if the token is not yet valid (accounting for clock skew)
     */
    public boolean isNotYetValid(Instant now, long clockSkewSeconds) {
        if (nbf == null) {
            return false;
        }
        return now.plusSeconds(clockSkewSeconds).isBefore(notBeforeTime());
    }
}
