/*
 * Copyright (c) 2026 Consensys Incorporated. All rights reserved.
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

package tech.pegasys.teku.statetransition.validation;

import static tech.pegasys.teku.statetransition.validation.InternalValidationResult.ACCEPT;
import static tech.pegasys.teku.statetransition.validation.InternalValidationResult.ignore;
import static tech.pegasys.teku.statetransition.validation.InternalValidationResult.reject;

import java.util.Optional;
import java.util.Set;
import tech.pegasys.teku.infrastructure.async.SafeFuture;
import tech.pegasys.teku.infrastructure.collections.LimitedSet;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.Spec;
import tech.pegasys.teku.spec.datastructures.operations.RandaoCommitmentRegistration;
import tech.pegasys.teku.spec.datastructures.operations.SignedRandaoCommitmentRegistration;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.BeaconStateEip8321;
import tech.pegasys.teku.spec.logic.common.operations.validation.OperationInvalidReason;
import tech.pegasys.teku.spec.logic.versions.eip8321.block.BlockProcessorEip8321;
import tech.pegasys.teku.storage.client.RecentChainData;

public class RandaoCommitmentRegistrationGossipValidator
    implements OperationValidator<SignedRandaoCommitmentRegistration> {

  private static final int SEEN_CACHE_SIZE = 16_384;

  private final Spec spec;
  private final RecentChainData recentChainData;
  private final Set<UInt64> seenValidatorIndices =
      LimitedSet.createSynchronizedLRU(SEEN_CACHE_SIZE);

  public RandaoCommitmentRegistrationGossipValidator(
      final Spec spec, final RecentChainData recentChainData) {
    this.spec = spec;
    this.recentChainData = recentChainData;
  }

  @Override
  public SafeFuture<InternalValidationResult> validateForGossip(
      final SignedRandaoCommitmentRegistration signedRegistration) {
    final RandaoCommitmentRegistration registration = signedRegistration.getMessage();
    final UInt64 validatorIndex = registration.getValidatorIndex();

    if (seenValidatorIndices.contains(validatorIndex)) {
      return SafeFuture.completedFuture(ignore("RANDAO commitment registration already seen"));
    }

    return recentChainData
        .getBestState()
        .orElseThrow(
            () ->
                new IllegalStateException(
                    "Unable to get best state for RANDAO commitment registration processing."))
        .thenApply(state -> validateAgainstState(state, signedRegistration));
  }

  @Override
  public Optional<OperationInvalidReason> validateForBlockInclusion(
      final BeaconState state, final SignedRandaoCommitmentRegistration signedRegistration) {
    final Optional<OperationInvalidReason> invalidReason =
        spec.atSlot(state.getSlot())
            .getOperationValidator()
            .validateRandaoCommitmentRegistration(
                state.getFork(), state, signedRegistration.getMessage());

    if (invalidReason.isPresent()) {
      return invalidReason;
    }

    final BlockProcessorEip8321 blockProcessor =
        (BlockProcessorEip8321) spec.getBlockProcessor(state.getSlot());
    if (!blockProcessor.isRandaoCommitmentRegistrationSignatureValid(state, signedRegistration)) {
      return Optional.of(() -> "RANDAO commitment registration signature is invalid");
    }

    return Optional.empty();
  }

  private InternalValidationResult validateAgainstState(
      final BeaconState state, final SignedRandaoCommitmentRegistration signedRegistration) {
    final RandaoCommitmentRegistration registration = signedRegistration.getMessage();
    final UInt64 validatorIndex = registration.getValidatorIndex();

    final var maybeEip8321State = state.toVersionEip8321();
    if (maybeEip8321State.isEmpty()) {
      return ignore("Head state is pre-EIP-8321");
    }

    if (!validatorIndex.isLessThan(UInt64.valueOf(state.getValidators().size()))) {
      return reject("Validator index is out of range");
    }

    if (registration.getCommitment().isZero()) {
      return reject("RANDAO commitment must not be zero");
    }

    final BeaconStateEip8321 eip8321State = maybeEip8321State.get();
    final int index = validatorIndex.intValue();

    if (!eip8321State.getRandaoCommitments().get(index).get().isZero()) {
      return ignore("Validator already has a RANDAO commitment");
    }

    final boolean pending =
        eip8321State.getPendingRandaoCommitments().stream()
            .anyMatch(entry -> entry.getValidatorIndex().equals(validatorIndex));
    if (pending) {
      return ignore("Validator already has a pending RANDAO commitment");
    }

    final BlockProcessorEip8321 blockProcessor =
        (BlockProcessorEip8321) spec.getBlockProcessor(state.getSlot());

    if (!blockProcessor.isRandaoCommitmentRegistrationSignatureValid(state, signedRegistration)) {
      return reject("Invalid RANDAO commitment registration signature");
    }

    if (!seenValidatorIndices.add(validatorIndex)) {
      return ignore("RANDAO commitment registration already seen");
    }

    return ACCEPT;
  }
}
