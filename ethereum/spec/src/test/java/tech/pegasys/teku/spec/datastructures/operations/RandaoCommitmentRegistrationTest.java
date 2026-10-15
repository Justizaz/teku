package tech.pegasys.teku.spec.datastructures.operations;

import static org.assertj.core.api.Assertions.assertThat;

import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;
import tech.pegasys.teku.bls.BLSSignature;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;

class RandaoCommitmentRegistrationTest {

    @Test
    void shouldSerializeAndDeserializeCorrectly() {
        final UInt64 validatorIndex = UInt64.valueOf(42);
        final Bytes32 commitment = Bytes32.ZERO;
        final BLSSignature signature = BLSSignature.empty();

        final RandaoCommitmentRegistration registration =
                new RandaoCommitmentRegistration(validatorIndex, commitment, signature);

        assertThat(registration.getValidatorIndex()).isEqualTo(validatorIndex);
        assertThat(registration.getCommitment()).isEqualTo(commitment);
        assertThat(registration.getSignature()).isEqualTo(signature);

        final RandaoCommitmentRegistration deserialized =
                RandaoCommitmentRegistration.SSZ_SCHEMA.sszDeserialize(registration.sszSerialize());

        assertThat(deserialized).isEqualTo(registration);
    }
}