package tech.pegasys.teku.spec.datastructures.operations;

import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;
import tech.pegasys.teku.bls.BLSSignature;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;

import static org.assertj.core.api.Assertions.assertThat;

class SignedRandaoCommitmentRegistrationTest {
    @Test
    void shouldSerializeAndDeserializeCorrectly() {
        final RandaoCommitmentRegistration message =
                new RandaoCommitmentRegistration(UInt64.valueOf(42), Bytes32.ZERO);

        final SignedRandaoCommitmentRegistration registration =
                new SignedRandaoCommitmentRegistration(message, BLSSignature.empty());

        assertThat(registration.getMessage()).isEqualTo(message);
        assertThat(registration.getSignature()).isEqualTo(BLSSignature.empty());

        final SignedRandaoCommitmentRegistration deserialized =
                SignedRandaoCommitmentRegistration.SSZ_SCHEMA.sszDeserialize(
                        registration.sszSerialize());

        assertThat(deserialized).isEqualTo(registration);
    }
}
