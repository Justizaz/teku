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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static tech.pegasys.teku.infrastructure.async.SafeFutureAssert.safeJoin;

import java.util.Optional;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.pegasys.teku.bls.BLS;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSSignature;
import tech.pegasys.teku.infrastructure.async.SafeFuture;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszBytes32;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.Spec;
import tech.pegasys.teku.spec.TestSpecFactory;
import tech.pegasys.teku.spec.constants.Domain;
import tech.pegasys.teku.spec.datastructures.interop.MockStartValidatorKeyPairFactory;
import tech.pegasys.teku.spec.datastructures.operations.PendingRandaoCommitment;
import tech.pegasys.teku.spec.datastructures.operations.RandaoCommitmentRegistration;
import tech.pegasys.teku.spec.datastructures.operations.SignedRandaoCommitmentRegistration;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.BeaconStateEip8321;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.BeaconStateSchemaEip8321;
import tech.pegasys.teku.spec.util.DataStructureUtil;
import tech.pegasys.teku.storage.client.RecentChainData;

public class RandaoCommitmentRegistrationGossipValidatorTest {

  private final Spec spec = TestSpecFactory.createMinimalEip8321();
  private final Spec specHeze = TestSpecFactory.createMinimalHeze();
  private final DataStructureUtil dataStructureUtil = new DataStructureUtil(spec);
  private final DataStructureUtil hezeDataStructureUtil = new DataStructureUtil(specHeze);
  private final RecentChainData recentChainData = mock(RecentChainData.class);

  private RandaoCommitmentRegistrationGossipValidator validator;
  private BeaconStateEip8321 state;
  private BLSKeyPair validatorKeyPair;

  private BeaconStateEip8321 createEip8321State(final int validatorCount) {
    final BeaconState hezeState =
        hezeDataStructureUtil.randomBeaconStateWithActiveValidators(validatorCount, UInt64.ZERO);
    return (BeaconStateEip8321)
        spec.getGenesisSpec().getStateUpgrade().orElseThrow().upgrade(hezeState);
  }

  @BeforeEach
  void setUp() {
    validatorKeyPair = new MockStartValidatorKeyPairFactory().generateKeyPairs(0, 1).get(0);
    final BeaconStateEip8321 baseState = createEip8321State(16);
    state =
        baseState.updatedEip8321(
            mutableState -> {
              mutableState
                  .getValidators()
                  .set(
                      0,
                      dataStructureUtil
                          .validatorBuilder()
                          .publicKey(validatorKeyPair.getPublicKey())
                          .build());
              mutableState.getRandaoCommitments().set(0, SszBytes32.of(Bytes32.ZERO));
              mutableState
                  .getPendingRandaoCommitments()
                  .setAll(
                      BeaconStateSchemaEip8321.required(mutableState.getBeaconStateSchema())
                          .getPendingRandaoCommitmentsSchema()
                          .of());
            });

    when(recentChainData.getBestState()).thenReturn(Optional.of(SafeFuture.completedFuture(state)));
    validator = new RandaoCommitmentRegistrationGossipValidator(spec, recentChainData);
  }

  private SignedRandaoCommitmentRegistration createSignedRegistration(
      final UInt64 validatorIndex, final Bytes32 commitment) {
    final RandaoCommitmentRegistration message =
        new RandaoCommitmentRegistration(validatorIndex, commitment);
    final Bytes32 domain =
        spec.atSlot(state.getSlot())
            .miscHelpers()
            .computeDomain(
                Domain.DOMAIN_RANDAO_COMMITMENT_REGISTRATION, state.getGenesisValidatorsRoot());
    final Bytes signingRoot =
        spec.atSlot(state.getSlot()).miscHelpers().computeSigningRoot(message, domain);
    final BLSSignature signature = BLS.sign(validatorKeyPair.getSecretKey(), signingRoot);
    return new SignedRandaoCommitmentRegistration(message, signature);
  }

  @Test
  void shouldAcceptValidRegistration() {
    final SignedRandaoCommitmentRegistration registration =
        createSignedRegistration(UInt64.ZERO, dataStructureUtil.randomBytes32());

    final InternalValidationResult result = safeJoin(validator.validateForGossip(registration));

    assertThat(result.isAccept()).isTrue();
  }

  @Test
  void shouldIgnoreAlreadySeenRegistration() {
    final SignedRandaoCommitmentRegistration registration =
        createSignedRegistration(UInt64.ZERO, dataStructureUtil.randomBytes32());

    final InternalValidationResult result1 = safeJoin(validator.validateForGossip(registration));
    assertThat(result1.isAccept()).isTrue();

    final InternalValidationResult result2 = safeJoin(validator.validateForGossip(registration));
    assertThat(result2.isIgnore()).isTrue();
    assertThat(result2.getDescription().orElse(""))
        .contains("RANDAO commitment registration already seen");
  }

  @Test
  void shouldRejectWhenValidatorIndexOutOfRange() {
    final UInt64 outOfRangeIndex = UInt64.valueOf(state.getValidators().size() + 10);
    final SignedRandaoCommitmentRegistration registration =
        createSignedRegistration(outOfRangeIndex, dataStructureUtil.randomBytes32());

    final InternalValidationResult result = safeJoin(validator.validateForGossip(registration));

    assertThat(result.isReject()).isTrue();
    assertThat(result.getDescription().orElse("")).contains("Validator index is out of range");
  }

  @Test
  void shouldRejectWhenCommitmentIsZero() {
    final SignedRandaoCommitmentRegistration registration =
        createSignedRegistration(UInt64.ZERO, Bytes32.ZERO);

    final InternalValidationResult result = safeJoin(validator.validateForGossip(registration));

    assertThat(result.isReject()).isTrue();
    assertThat(result.getDescription().orElse("")).contains("RANDAO commitment must not be zero");
  }

  @Test
  void shouldIgnoreWhenValidatorAlreadyHasCommitment() {
    state =
        state.updatedEip8321(
            mutableState ->
                mutableState
                    .getRandaoCommitments()
                    .set(0, SszBytes32.of(dataStructureUtil.randomBytes32())));
    when(recentChainData.getBestState()).thenReturn(Optional.of(SafeFuture.completedFuture(state)));

    final SignedRandaoCommitmentRegistration registration =
        createSignedRegistration(UInt64.ZERO, dataStructureUtil.randomBytes32());

    final InternalValidationResult result = safeJoin(validator.validateForGossip(registration));

    assertThat(result.isIgnore()).isTrue();
    assertThat(result.getDescription().orElse(""))
        .contains("Validator already has a RANDAO commitment");
  }

  @Test
  void shouldIgnoreWhenValidatorAlreadyHasPendingCommitment() {
    final PendingRandaoCommitment pending =
        new PendingRandaoCommitment(
            UInt64.ZERO, dataStructureUtil.randomBytes32(), UInt64.valueOf(100));
    state =
        state.updatedEip8321(
            mutableState ->
                mutableState
                    .getPendingRandaoCommitments()
                    .setAll(
                        BeaconStateSchemaEip8321.required(mutableState.getBeaconStateSchema())
                            .getPendingRandaoCommitmentsSchema()
                            .of(pending)));
    when(recentChainData.getBestState()).thenReturn(Optional.of(SafeFuture.completedFuture(state)));

    final SignedRandaoCommitmentRegistration registration =
        createSignedRegistration(UInt64.ZERO, dataStructureUtil.randomBytes32());

    final InternalValidationResult result = safeJoin(validator.validateForGossip(registration));

    assertThat(result.isIgnore()).isTrue();
    assertThat(result.getDescription().orElse(""))
        .contains("Validator already has a pending RANDAO commitment");
  }

  @Test
  void shouldRejectInvalidSignature() {
    final RandaoCommitmentRegistration message =
        new RandaoCommitmentRegistration(UInt64.ZERO, dataStructureUtil.randomBytes32());
    final SignedRandaoCommitmentRegistration registration =
        new SignedRandaoCommitmentRegistration(message, dataStructureUtil.randomSignature());

    final InternalValidationResult result = safeJoin(validator.validateForGossip(registration));

    assertThat(result.isReject()).isTrue();
    assertThat(result.getDescription().orElse(""))
        .contains("Invalid RANDAO commitment registration signature");
  }

  @Test
  void shouldIgnoreWhenHeadStateIsPreEip8321() {
    final BeaconState hezeState = hezeDataStructureUtil.randomBeaconState(16);
    when(recentChainData.getBestState())
        .thenReturn(Optional.of(SafeFuture.completedFuture(hezeState)));

    final SignedRandaoCommitmentRegistration registration =
        createSignedRegistration(UInt64.ZERO, dataStructureUtil.randomBytes32());

    final InternalValidationResult result = safeJoin(validator.validateForGossip(registration));

    assertThat(result.isIgnore()).isTrue();
    assertThat(result.getDescription().orElse("")).contains("Head state is pre-EIP-8321");
  }

  @Test
  void shouldValidateForBlockInclusion() {
    final SignedRandaoCommitmentRegistration validRegistration =
        createSignedRegistration(UInt64.ZERO, dataStructureUtil.randomBytes32());

    assertThat(validator.validateForBlockInclusion(state, validRegistration)).isEmpty();

    final SignedRandaoCommitmentRegistration invalidSignature =
        new SignedRandaoCommitmentRegistration(
            validRegistration.getMessage(), dataStructureUtil.randomSignature());
    assertThat(validator.validateForBlockInclusion(state, invalidSignature)).isPresent();
  }
}
