package com.godaddy.ans.sdk.transparency.scitt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link CoseEnvelope} defensive copy behavior.
 */
class CoseEnvelopeTest {

    @Test
    @DisplayName("mutating source arrays should not affect envelope")
    void mutatingSourceArraysShouldNotAffectEnvelope() {
        byte[] headerBytes = {0x01, 0x02, 0x03};
        byte[] payload = {0x04, 0x05, 0x06};
        byte[] signature = {0x07, 0x08, 0x09};

        CoseEnvelope envelope = new CoseEnvelope(null, headerBytes, payload, signature);

        // Mutate the original arrays
        headerBytes[0] = (byte) 0xFF;
        payload[0] = (byte) 0xFF;
        signature[0] = (byte) 0xFF;

        // Envelope should be unaffected
        assertThat(envelope.protectedHeaderBytes()[0]).isEqualTo((byte) 0x01);
        assertThat(envelope.payload()[0]).isEqualTo((byte) 0x04);
        assertThat(envelope.signature()[0]).isEqualTo((byte) 0x07);
    }

    @Test
    @DisplayName("mutating accessor results should not affect envelope")
    void mutatingAccessorResultsShouldNotAffectEnvelope() {
        byte[] headerBytes = {0x01, 0x02, 0x03};
        byte[] payload = {0x04, 0x05, 0x06};
        byte[] signature = {0x07, 0x08, 0x09};

        CoseEnvelope envelope = new CoseEnvelope(null, headerBytes, payload, signature);

        // Mutate the arrays returned by accessors
        envelope.protectedHeaderBytes()[0] = (byte) 0xFF;
        envelope.payload()[0] = (byte) 0xFF;
        envelope.signature()[0] = (byte) 0xFF;

        // Envelope should be unaffected
        assertThat(envelope.protectedHeaderBytes()[0]).isEqualTo((byte) 0x01);
        assertThat(envelope.payload()[0]).isEqualTo((byte) 0x04);
        assertThat(envelope.signature()[0]).isEqualTo((byte) 0x07);
    }

    @Test
    @DisplayName("null byte arrays should be handled gracefully")
    void nullByteArraysShouldBeHandledGracefully() {
        CoseEnvelope envelope = new CoseEnvelope(null, null, null, null);

        assertThat(envelope.protectedHeaderBytes()).isNull();
        assertThat(envelope.payload()).isNull();
        assertThat(envelope.signature()).isNull();
    }

    @Test
    @DisplayName("equals should work correctly with defensive copies")
    void equalsShouldWorkCorrectlyWithDefensiveCopies() {
        byte[] headerBytes = {0x01, 0x02};
        byte[] payload = {0x03, 0x04};
        byte[] signature = {0x05, 0x06};

        CoseEnvelope envelope1 = new CoseEnvelope(null, headerBytes, payload, signature);
        CoseEnvelope envelope2 = new CoseEnvelope(
            null, new byte[]{0x01, 0x02}, new byte[]{0x03, 0x04}, new byte[]{0x05, 0x06});

        assertThat(envelope1).isEqualTo(envelope2);
        assertThat(envelope1.hashCode()).isEqualTo(envelope2.hashCode());
    }
}
