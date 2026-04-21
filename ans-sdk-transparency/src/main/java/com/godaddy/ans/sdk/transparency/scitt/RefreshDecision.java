package com.godaddy.ans.sdk.transparency.scitt;

import java.security.PublicKey;
import java.util.Map;

/**
 * Result of a root key cache refresh decision.
 *
 * <p>Used by the SCITT verification flow to determine whether a cache refresh
 * should be attempted when a key is not found in the trust store.</p>
 *
 * @param action the action to take
 * @param reason human-readable explanation (for logging/debugging)
 * @param keys the refreshed keys (only present if action is REFRESHED)
 */
public record RefreshDecision(RefreshAction action, String reason, Map<String, PublicKey> keys) {

    /**
     * Actions that can be taken when a key is not found in cache.
     */
    public enum RefreshAction {
        /** Refresh not allowed - artifact is invalid (too old or from future) */
        REJECT,
        /** Refresh not allowed now - try again later (cooldown in effect) */
        DEFER,
        /** Cache was refreshed - use the new keys for retry */
        REFRESHED
    }

    /**
     * Creates a REJECT decision indicating the artifact is invalid.
     *
     * @param reason explanation of why the artifact is invalid
     * @return a REJECT decision
     */
    public static RefreshDecision reject(String reason) {
        return new RefreshDecision(RefreshAction.REJECT, reason, null);
    }

    /**
     * Creates a DEFER decision indicating refresh should be retried later.
     *
     * @param reason explanation of why refresh was deferred
     * @return a DEFER decision
     */
    public static RefreshDecision defer(String reason) {
        return new RefreshDecision(RefreshAction.DEFER, reason, null);
    }

    /**
     * Creates a REFRESHED decision with the new keys.
     *
     * @param keys the refreshed root keys
     * @return a REFRESHED decision
     */
    public static RefreshDecision refreshed(Map<String, PublicKey> keys) {
        return new RefreshDecision(RefreshAction.REFRESHED, null, keys);
    }

    /**
     * Returns true if the cache was successfully refreshed.
     *
     * @return true if action is REFRESHED
     */
    public boolean isRefreshed() {
        return action == RefreshAction.REFRESHED;
    }
}
