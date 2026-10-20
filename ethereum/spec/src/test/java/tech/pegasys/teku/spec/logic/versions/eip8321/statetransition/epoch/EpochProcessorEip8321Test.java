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

package tech.pegasys.teku.spec.logic.versions.eip8321.statetransition.epoch;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.pegasys.teku.infrastructure.ssz.collections.SszPrimitiveVector;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszUInt64;
import tech.pegasys.teku.infrastructure.ssz.schema.SszListSchema;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.Spec;
import tech.pegasys.teku.spec.TestSpecFactory;
import tech.pegasys.teku.spec.datastructures.operations.PendingRandaoCommitment;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.BeaconStateEip8321;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.BeaconStateSchemaEip8321;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.MutableBeaconStateEip8321;
import tech.pegasys.teku.spec.logic.common.statetransition.exceptions.EpochProcessingException;
import tech.pegasys.teku.spec.util.DataStructureUtil;

class EpochProcessorEip8321Test {

  private final Spec spec = TestSpecFactory.createMinimalEip8321();
  private final DataStructureUtil dataStructureUtil = new DataStructureUtil(spec);

  private EpochProcessorEip8321 epochProcessor;

  @BeforeEach
  void setUp() {
    epochProcessor = (EpochProcessorEip8321) spec.getGenesisSpec().getEpochProcessor();
    assertThat(epochProcessor).isNotNull();
  }

  @Test
  void processPendingRandaoCommitments_shouldActivateDueCommitmentAtExactBoundary() {
    final BeaconStateEip8321 baseState = createEip8321State(8, UInt64.valueOf(10 * spec.getGenesisSpecConfig().getSlotsPerEpoch()));
    final UInt64 currentEpoch = spec.computeEpochAtSlot(baseState.getSlot());
    assertThat(currentEpoch).isEqualTo(UInt64.valueOf(10));
    final UInt64 nextEpoch = currentEpoch.plus(1); // 11

    final Bytes32 commitment = dataStructureUtil.randomBytes32();
    final PendingRandaoCommitment pending =
        new PendingRandaoCommitment(UInt64.ZERO, commitment, nextEpoch);

    final BeaconStateEip8321 preState =
        baseState.updatedEip8321(
            state ->
                state.setPendingRandaoCommitments(
                    getPendingSchema(state).createFromElements(List.of(pending))));

    assertThat(preState.getRandaoCommitments().get(0).get()).isEqualTo(Bytes32.ZERO);
    assertThat(preState.getPendingRandaoCommitments().size()).isEqualTo(1);

    final BeaconStateEip8321 postState =
        preState.updatedEip8321(state -> epochProcessor.processPendingRandaoCommitments(state));

    assertThat(postState.getRandaoCommitments().get(0).get()).isEqualTo(commitment);
    assertThat(postState.getPendingRandaoCommitments().isEmpty()).isTrue();
  }

  @Test
  void processPendingRandaoCommitments_shouldActivateDueCommitmentWhenActivationEpochLessThanNextEpoch() {
    final BeaconStateEip8321 baseState = createEip8321State(8, UInt64.valueOf(10 * spec.getGenesisSpecConfig().getSlotsPerEpoch()));
    final UInt64 currentEpoch = spec.computeEpochAtSlot(baseState.getSlot()); // 10

    final Bytes32 commitment = dataStructureUtil.randomBytes32();
    final PendingRandaoCommitment pending =
        new PendingRandaoCommitment(UInt64.valueOf(1), commitment, currentEpoch); // activationEpoch = 10 < 11

    final BeaconStateEip8321 preState =
        baseState.updatedEip8321(
            state ->
                state.setPendingRandaoCommitments(
                    getPendingSchema(state).createFromElements(List.of(pending))));

    final BeaconStateEip8321 postState =
        preState.updatedEip8321(state -> epochProcessor.processPendingRandaoCommitments(state));

    assertThat(postState.getRandaoCommitments().get(1).get()).isEqualTo(commitment);
    assertThat(postState.getPendingRandaoCommitments().isEmpty()).isTrue();
  }

  @Test
  void processPendingRandaoCommitments_shouldRetainFutureCommitment() {
    final BeaconStateEip8321 baseState = createEip8321State(8, UInt64.valueOf(10 * spec.getGenesisSpecConfig().getSlotsPerEpoch()));
    final UInt64 currentEpoch = spec.computeEpochAtSlot(baseState.getSlot()); // 10
    final UInt64 futureActivationEpoch = currentEpoch.plus(2); // 12 > nextEpoch (11)

    final Bytes32 commitment = dataStructureUtil.randomBytes32();
    final PendingRandaoCommitment pending =
        new PendingRandaoCommitment(UInt64.valueOf(2), commitment, futureActivationEpoch);

    final BeaconStateEip8321 preState =
        baseState.updatedEip8321(
            state ->
                state.setPendingRandaoCommitments(
                    getPendingSchema(state).createFromElements(List.of(pending))));

    final BeaconStateEip8321 postState =
        preState.updatedEip8321(state -> epochProcessor.processPendingRandaoCommitments(state));

    assertThat(postState.getRandaoCommitments().get(2).get()).isEqualTo(Bytes32.ZERO);
    assertThat(postState.getPendingRandaoCommitments().size()).isEqualTo(1);
    assertThat(postState.getPendingRandaoCommitments().get(0)).isEqualTo(pending);
  }

  @Test
  void processPendingRandaoCommitments_shouldActivateEligiblePrefixAndRetainSuffix() {
    final BeaconStateEip8321 baseState = createEip8321State(
            8,
            UInt64.valueOf(10 * spec.getGenesisSpecConfig().getSlotsPerEpoch()));
    final UInt64 currentEpoch = spec.computeEpochAtSlot(baseState.getSlot()); // 10
    final UInt64 nextEpoch = currentEpoch.plus(1); // 11

    assertThat(currentEpoch).isEqualTo(UInt64.valueOf(10));
    assertThat(nextEpoch).isEqualTo(UInt64.valueOf(11));

    final Bytes32 commitment0 = dataStructureUtil.randomBytes32();
    final Bytes32 commitment1 = dataStructureUtil.randomBytes32();
    final Bytes32 commitment2 = dataStructureUtil.randomBytes32();
    final Bytes32 commitment3 = dataStructureUtil.randomBytes32();

    final PendingRandaoCommitment pending0 =
        new PendingRandaoCommitment(UInt64.ZERO, commitment0, currentEpoch); // 10: due
    final PendingRandaoCommitment pending1 =
        new PendingRandaoCommitment(UInt64.ONE, commitment1, nextEpoch); // 11: duo
    final PendingRandaoCommitment pending2 =
        new PendingRandaoCommitment(UInt64.valueOf(2), commitment2, nextEpoch.plus(2)); // 13: future
    final PendingRandaoCommitment pending3 =
        new PendingRandaoCommitment(UInt64.valueOf(3), commitment3, nextEpoch.plus(3)); // 14: future

    final BeaconStateEip8321 preState =
        baseState.updatedEip8321(
            state ->
                state.setPendingRandaoCommitments(
                    getPendingSchema(state).createFromElements(List.of(pending0, pending1, pending2, pending3))));

    final BeaconStateEip8321 postState =
        preState.updatedEip8321(state -> epochProcessor.processPendingRandaoCommitments(state));

    // The eligible prefix was activated.
    assertThat(postState.getRandaoCommitments().get(0).get()).isEqualTo(commitment0);
    assertThat(postState.getRandaoCommitments().get(1).get()).isEqualTo(commitment1);

    // Processing stopped at the first future entry.
    assertThat(postState.getRandaoCommitments().get(2).get()).isEqualTo(Bytes32.ZERO);
    assertThat(postState.getRandaoCommitments().get(3).get()).isEqualTo(Bytes32.ZERO);

    // The unprocessed suffix remains in the same order.
    assertThat(postState.getPendingRandaoCommitments()).containsExactly(pending2, pending3);
  }

  @Test
  void processPendingRandaoCommitments_shouldDoNothingWhenQueueIsEmpty() {
    final BeaconStateEip8321 baseState = createEip8321State(8, UInt64.ZERO);
    assertThat(baseState.getPendingRandaoCommitments().isEmpty()).isTrue();

    final BeaconStateEip8321 postState =
        baseState.updatedEip8321(state -> epochProcessor.processPendingRandaoCommitments(state));

    assertThat(postState.getPendingRandaoCommitments().isEmpty()).isTrue();
    for (int i = 0; i < 8; i++) {
      assertThat(postState.getRandaoCommitments().get(i).get()).isEqualTo(Bytes32.ZERO);
    }
  }

  @Test
  void processEpoch_shouldActivateDuePendingCommitmentsDuringEpochTransition()
      throws EpochProcessingException {
    final BeaconStateEip8321 baseState = createEip8321State(8, UInt64.ZERO);
    final UInt64 currentEpoch = spec.computeEpochAtSlot(baseState.getSlot()); // 0
    final UInt64 nextEpoch = currentEpoch.plus(1); // 1

    final Bytes32 commitment = dataStructureUtil.randomBytes32();
    final PendingRandaoCommitment pendingDue =
        new PendingRandaoCommitment(UInt64.ZERO, commitment, nextEpoch);
    final PendingRandaoCommitment pendingFuture =
        new PendingRandaoCommitment(
            UInt64.valueOf(1), dataStructureUtil.randomBytes32(), nextEpoch.plus(1));

    final BeaconStateEip8321 preState =
        baseState.updatedEip8321(
            state ->
                state.setPendingRandaoCommitments(
                    getPendingSchema(state).createFromElements(List.of(pendingDue, pendingFuture))));

    final BeaconState postState = epochProcessor.processEpoch(preState);
    final BeaconStateEip8321 postStateEip8321 = BeaconStateEip8321.required(postState);

    assertThat(postStateEip8321.getRandaoCommitments().get(0).get()).isEqualTo(commitment);
    assertThat(postStateEip8321.getRandaoCommitments().get(1).get()).isEqualTo(Bytes32.ZERO);
    assertThat(postStateEip8321.getPendingRandaoCommitments().size()).isEqualTo(1);
    assertThat(postStateEip8321.getPendingRandaoCommitments().get(0)).isEqualTo(pendingFuture);
  }

  private BeaconStateEip8321 createEip8321State(final int validatorCount, final UInt64 slot) {
    final Spec specGloas = TestSpecFactory.createMinimalGloas();
    final DataStructureUtil gloasUtil = new DataStructureUtil(specGloas);
    final BeaconState rawState =
        gloasUtil.randomBeaconStateWithActiveValidators(validatorCount, slot);
    final SszPrimitiveVector<UInt64, SszUInt64> noSlashings =
        gloasUtil.randomSszPrimitiveVector(
            rawState.getBeaconStateSchema().getSlashingsSchema(), () -> UInt64.ZERO);
    final BeaconState baseState = rawState.updated(state -> state.setSlashings(noSlashings));
    return (BeaconStateEip8321)
        spec.getGenesisSpec().getStateUpgrade().orElseThrow().upgrade(baseState);
  }

  private SszListSchema<PendingRandaoCommitment, ?> getPendingSchema(
      final MutableBeaconStateEip8321 state) {
    return BeaconStateSchemaEip8321.required(state.getBeaconStateSchema())
        .getPendingRandaoCommitmentsSchema();
  }
}
