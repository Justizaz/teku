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

import static tech.pegasys.teku.spec.logic.common.operations.validation.OperationInvalidReason.check;
import static tech.pegasys.teku.spec.logic.common.operations.validation.OperationInvalidReason.firstOf;
import static tech.pegasys.teku.spec.logic.versions.eip8321.operations.validation.RandaoCommitmentRegistrationValidator.RandaoCommitmentRegistrationInvalidReason.invalidStateVersion;
import static tech.pegasys.teku.spec.logic.versions.eip8321.operations.validation.RandaoCommitmentRegistrationValidator.RandaoCommitmentRegistrationInvalidReason.invalidValidatorIndex;
import static tech.pegasys.teku.spec.logic.versions.eip8321.operations.validation.RandaoCommitmentRegistrationValidator.RandaoCommitmentRegistrationInvalidReason.validatorAlreadyRegistered;
import static tech.pegasys.teku.spec.logic.versions.eip8321.operations.validation.RandaoCommitmentRegistrationValidator.RandaoCommitmentRegistrationInvalidReason.validatorHasPendingRegistration;
import static tech.pegasys.teku.spec.logic.versions.eip8321.operations.validation.RandaoCommitmentRegistrationValidator.RandaoCommitmentRegistrationInvalidReason.zeroCommitment;

import java.util.Optional;

import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.datastructures.operations.RandaoCommitmentRegistration;
import tech.pegasys.teku.spec.datastructures.state.Fork;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.BeaconStateEip8321;
import tech.pegasys.teku.spec.logic.common.operations.validation.OperationInvalidReason;
import tech.pegasys.teku.spec.logic.common.operations.validation.OperationStateTransitionValidator;

public class RandaoCommitmentRegistrationValidator
        implements OperationStateTransitionValidator<RandaoCommitmentRegistration> {

    public RandaoCommitmentRegistrationValidator() {
    }

    @Override
    public Optional<OperationInvalidReason> validate(
            final Fork fork,
            final BeaconState state,
            final RandaoCommitmentRegistration registration) {
        return firstOf(
                () -> checkValidatorIndex(state, registration.getValidatorIndex()),
                () -> checkCommitment(registration),
                () -> checkUnregistered(state, registration.getValidatorIndex()),
                () -> checkNotPending(state, registration.getValidatorIndex()));
    }

    private Optional<OperationInvalidReason> checkValidatorIndex(
            final BeaconState state, final UInt64 validatorIndex) {
        return check(
                validatorIndex.isLessThan(state.getValidators().size()),
                invalidValidatorIndex(validatorIndex));
    }

    private Optional<OperationInvalidReason> checkCommitment(
            final RandaoCommitmentRegistration registration) {
        return check(!registration.getCommitment().isZero(), zeroCommitment());
    }

    private Optional<OperationInvalidReason> checkUnregistered(
            final BeaconState state, final UInt64 validatorIndex) {
        final Optional<BeaconStateEip8321> stateEip8321 = state.toVersionEip8321();
        if (stateEip8321.isEmpty()) {
            return Optional.of(invalidStateVersion());
        }
        final int index = validatorIndex.intValue();
        return check(
                stateEip8321.get().getRandaoCommitments().get(index).get().isZero(),
                validatorAlreadyRegistered(validatorIndex));
    }

    private Optional<OperationInvalidReason> checkNotPending(
            final BeaconState state, final UInt64 validatorIndex) {
        final Optional<BeaconStateEip8321> stateEip8321 = state.toVersionEip8321();
        if (stateEip8321.isEmpty()) {
            return Optional.of(invalidStateVersion());
        }
        final boolean alreadyPending =
                stateEip8321.get().getPendingRandaoCommitments().stream()
                        .anyMatch(pending -> pending.getValidatorIndex().equals(validatorIndex));
        return check(!alreadyPending, validatorHasPendingRegistration(validatorIndex));
    }

    public static class RandaoCommitmentRegistrationInvalidReason {
        public static OperationInvalidReason invalidValidatorIndex(final UInt64 validatorIndex) {
            return () -> String.format("Invalid validator index: %s", validatorIndex);
        }

        public static OperationInvalidReason zeroCommitment() {
            return () -> "Commitment cannot be zero";
        }

        public static OperationInvalidReason invalidStateVersion() {
            return () -> "State is not an EIP-8321 state";
        }

        public static OperationInvalidReason validatorAlreadyRegistered(final UInt64 validatorIndex) {
            return () ->
                    String.format("Validator %s already has a registered commitment", validatorIndex);
        }

        public static OperationInvalidReason validatorHasPendingRegistration(final UInt64 validatorIndex) {
            return () ->
                    String.format("Validator %s already has a pending registration", validatorIndex);
        }
    }
}
