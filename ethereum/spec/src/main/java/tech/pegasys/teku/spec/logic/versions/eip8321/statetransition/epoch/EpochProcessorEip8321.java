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

import tech.pegasys.teku.infrastructure.ssz.SszMutableList;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszBytes32;
import tech.pegasys.teku.infrastructure.time.TimeProvider;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.config.SpecConfigEip8321;
import tech.pegasys.teku.spec.datastructures.operations.PendingRandaoCommitment;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.MutableBeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.BeaconStateSchemaEip8321;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.MutableBeaconStateEip8321;
import tech.pegasys.teku.spec.logic.common.statetransition.epoch.status.ValidatorStatusFactory;
import tech.pegasys.teku.spec.logic.common.util.BeaconStateUtil;
import tech.pegasys.teku.spec.logic.common.util.ValidatorsUtil;
import tech.pegasys.teku.spec.logic.versions.gloas.helpers.BeaconStateAccessorsGloas;
import tech.pegasys.teku.spec.logic.versions.gloas.helpers.BeaconStateMutatorsGloas;
import tech.pegasys.teku.spec.logic.versions.gloas.helpers.MiscHelpersGloas;
import tech.pegasys.teku.spec.logic.versions.gloas.statetransition.epoch.EpochProcessorGloas;
import tech.pegasys.teku.spec.schemas.SchemaDefinitionsEip8321;

public class EpochProcessorEip8321 extends EpochProcessorGloas {

  public EpochProcessorEip8321(
      final SpecConfigEip8321 specConfig,
      final MiscHelpersGloas miscHelpers,
      final BeaconStateAccessorsGloas beaconStateAccessors,
      final BeaconStateMutatorsGloas beaconStateMutators,
      final ValidatorsUtil validatorsUtil,
      final BeaconStateUtil beaconStateUtil,
      final ValidatorStatusFactory validatorStatusFactory,
      final SchemaDefinitionsEip8321 schemaDefinitions,
      final TimeProvider timeProvider) {
    super(
        specConfig,
        miscHelpers,
        beaconStateAccessors,
        beaconStateMutators,
        validatorsUtil,
        beaconStateUtil,
        validatorStatusFactory,
        schemaDefinitions,
        timeProvider);
  }

  /**
   * process_pending_randao_commitments
   *
   * <p>EIP-8321: Drains pending commitments whose activation_epoch <= next_epoch, setting
   * randao_commitments[validator_index] = commitment, and retaining unactivated entries in
   * pending_randao_commitments.
   */
  @Override
  public void processPendingRandaoCommitments(final MutableBeaconState state) {
    final MutableBeaconStateEip8321 stateEip8321 = MutableBeaconStateEip8321.required(state);
    final UInt64 nextEpoch = beaconStateAccessors.getCurrentEpoch(state).plus(1);
    final SszMutableList<PendingRandaoCommitment> pendingList =
        stateEip8321.getPendingRandaoCommitments();
    final SszMutableList<SszBytes32> randaoCommitments = stateEip8321.getRandaoCommitments();

    int nextPendingCommitment = 0;
    for (final PendingRandaoCommitment pending : pendingList) {
      if (pending.getActivationEpoch().isGreaterThan(nextEpoch)) {
        break;
      }

      randaoCommitments.set(
            pending.getValidatorIndex().intValue(),
            SszBytes32.of(pending.getCommitment()));

      nextPendingCommitment++;
    }

    stateEip8321.setPendingRandaoCommitments(
        BeaconStateSchemaEip8321.required(stateEip8321.getBeaconStateSchema())
            .getPendingRandaoCommitmentsSchema()
            .createFromElements(
                    pendingList
                            .asList()
                            .subList(nextPendingCommitment, pendingList.size())));
  }
}
