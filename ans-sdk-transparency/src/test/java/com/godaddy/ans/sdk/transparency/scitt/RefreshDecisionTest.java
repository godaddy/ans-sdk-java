package com.godaddy.ans.sdk.transparency.scitt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("RefreshDecision tests")
class RefreshDecisionTest {

    @Test
    @DisplayName("reject() should create REJECT decision with reason")
    void rejectShouldCreateRejectDecision() {
        RefreshDecision decision = RefreshDecision.reject("test reason");

        assertThat(decision.action()).isEqualTo(RefreshDecision.RefreshAction.REJECT);
        assertThat(decision.reason()).isEqualTo("test reason");
        assertThat(decision.keys()).isNull();
        assertThat(decision.isRefreshed()).isFalse();
    }

    @Test
    @DisplayName("defer() should create DEFER decision with reason")
    void deferShouldCreateDeferDecision() {
        RefreshDecision decision = RefreshDecision.defer("cooldown active");

        assertThat(decision.action()).isEqualTo(RefreshDecision.RefreshAction.DEFER);
        assertThat(decision.reason()).isEqualTo("cooldown active");
        assertThat(decision.keys()).isNull();
        assertThat(decision.isRefreshed()).isFalse();
    }

    @Test
    @DisplayName("refreshed() should create REFRESHED decision with keys")
    void refreshedShouldCreateRefreshedDecision() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        Map<String, PublicKey> keys = Map.of("test-key-id", publicKey);
        RefreshDecision decision = RefreshDecision.refreshed(keys);

        assertThat(decision.action()).isEqualTo(RefreshDecision.RefreshAction.REFRESHED);
        assertThat(decision.reason()).isNull();
        assertThat(decision.keys()).isEqualTo(keys);
        assertThat(decision.isRefreshed()).isTrue();
    }

    @Test
    @DisplayName("isRefreshed() should return true only for REFRESHED action")
    void isRefreshedShouldReturnTrueOnlyForRefreshed() {
        assertThat(RefreshDecision.reject("reason").isRefreshed()).isFalse();
        assertThat(RefreshDecision.defer("reason").isRefreshed()).isFalse();
        assertThat(RefreshDecision.refreshed(Map.of()).isRefreshed()).isTrue();
    }
}
