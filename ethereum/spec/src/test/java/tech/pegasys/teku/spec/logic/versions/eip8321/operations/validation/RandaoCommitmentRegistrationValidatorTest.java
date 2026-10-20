/*
 * Copyright Consensys Software Inc., 2026
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package tech.pegasys.teku.spec.logic.versions.eip8321.operations.validation;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Optional;

import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszBytes32;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.Spec;
import tech.pegasys.teku.spec.TestSpecFactory;
import tech.pegasys.teku.spec.datastructures.operations.PendingRandaoCommitment;
import tech.pegasys.teku.spec.datastructures.operations.RandaoCommitmentRegistration;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.BeaconStateEip8321;
import tech.pegasys.teku.spec.logic.common.operations.validation.OperationInvalidReason;
import tech.pegasys.teku.spec.util.DataStructureUtil;

class RandaoCommitmentRegistrationValidatorTest {

    private final Spec spec = TestSpecFactory.createMinimalEip8321();
    private final Spec specGloas = TestSpecFactory.createMinimalGloas();
    private final DataStructureUtil dataStructureUtil = new DataStructureUtil(spec);
    private final DataStructureUtil gloasDataStructureUtil = new DataStructureUtil(specGloas);
    private final RandaoCommitmentRegistrationValidator validator =
            new RandaoCommitmentRegistrationValidator();

    private BeaconStateEip8321 createEip8321State(final int validatorCount) {
        final BeaconState gloasState =
                gloasDataStructureUtil.randomBeaconStateWithActiveValidators(validatorCount, UInt64.ZERO);
        return (BeaconStateEip8321)
                spec.getGenesisSpec().getStateUpgrade().orElseThrow().upgrade(gloasState);
    }

    @Test
    void validate_validRegistration_shouldSucceed() {
        final BeaconStateEip8321 state = createEip8321State(32);
        final UInt64 validatorIndex = UInt64.valueOf(0);
        final Bytes32 commitment = dataStructureUtil.randomBytes32();
        final RandaoCommitmentRegistration registration =
                new RandaoCommitmentRegistration(validatorIndex, commitment);

        final Optional<OperationInvalidReason> result =
                validator.validate(state.getFork(), state, registration);

        assertThat(result).isEmpty();
    }

    @Test
    void validate_invalidValidatorIndex_shouldFail() {
        final BeaconStateEip8321 state = createEip8321State(16);
        final UInt64 outOfBoundsIndex = UInt64.valueOf(16);
        final Bytes32 commitment = dataStructureUtil.randomBytes32();
        final RandaoCommitmentRegistration registration =
                new RandaoCommitmentRegistration(outOfBoundsIndex, commitment);

        final Optional<OperationInvalidReason> result =
                validator.validate(state.getFork(), state, registration);

        assertThat(result).isPresent();
        assertThat(result.get().describe()).contains("Invalid validator index: 16");
    }

    @Test
    void validate_zeroCommitment_shouldFail() {
        final BeaconStateEip8321 state = createEip8321State(16);
        final UInt64 validatorIndex = UInt64.valueOf(0);
        final RandaoCommitmentRegistration registration =
                new RandaoCommitmentRegistration(validatorIndex, Bytes32.ZERO);

        final Optional<OperationInvalidReason> result =
                validator.validate(state.getFork(), state, registration);

        assertThat(result).isPresent();
        assertThat(result.get().describe()).contains("Commitment cannot be zero");
    }

    @Test
    void validate_alreadyRegisteredValidator_shouldFail() {
        final BeaconStateEip8321 baseState = createEip8321State(16);
        final int validatorIndex = 3;
        final Bytes32 existingCommitment = dataStructureUtil.randomBytes32();

        final BeaconStateEip8321 state =
                baseState.updatedEip8321(
                        mutableState ->
                                mutableState
                                        .getRandaoCommitments()
                                        .set(validatorIndex, SszBytes32.of(existingCommitment)));

        final RandaoCommitmentRegistration registration =
                new RandaoCommitmentRegistration(
                        UInt64.valueOf(validatorIndex), dataStructureUtil.randomBytes32());

        final Optional<OperationInvalidReason> result =
                validator.validate(state.getFork(), state, registration);

        assertThat(result).isPresent();
        assertThat(result.get().describe())
                .contains(String.format("Validator %d already has a registered commitment", validatorIndex));
    }

    @Test
    void validate_alreadyPendingRegistration_shouldFail() {
        final BeaconStateEip8321 baseState = createEip8321State(16);
        final UInt64 validatorIndex = UInt64.valueOf(2);
        final PendingRandaoCommitment pending =
                new PendingRandaoCommitment(
                        validatorIndex, dataStructureUtil.randomBytes32(), UInt64.valueOf(10));

        final BeaconStateEip8321 state =
                baseState.updatedEip8321(
                        mutableState -> mutableState.getPendingRandaoCommitments().append(pending));

        final RandaoCommitmentRegistration registration =
                new RandaoCommitmentRegistration(validatorIndex, dataStructureUtil.randomBytes32());

        final Optional<OperationInvalidReason> result =
                validator.validate(state.getFork(), state, registration);

        assertThat(result).isPresent();
        assertThat(result.get().describe())
                .contains(String.format("Validator %s already has a pending registration", validatorIndex));
    }

    @Test
    void validate_nonEip8321State_shouldFail() {
        final BeaconState stateGloas = gloasDataStructureUtil.randomBeaconState(16);

        final RandaoCommitmentRegistration registration =
                new RandaoCommitmentRegistration(UInt64.ZERO, dataStructureUtil.randomBytes32());

        final Optional<OperationInvalidReason> result =
                validator.validate(stateGloas.getFork(), stateGloas, registration);

        assertThat(result).isPresent();
        assertThat(result.get().describe()).contains("State is not an EIP-8321 state");
    }
}
