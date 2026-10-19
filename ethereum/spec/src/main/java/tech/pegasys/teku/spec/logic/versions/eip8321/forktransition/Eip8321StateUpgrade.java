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

package tech.pegasys.teku.spec.logic.versions.eip8321.forktransition;

import org.apache.tuweni.bytes.Bytes32;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszBytes32;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.config.SpecConfigEip8321;
import tech.pegasys.teku.spec.config.SpecConfigHeze;
import tech.pegasys.teku.spec.datastructures.state.Fork;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.common.BeaconStateFields;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.BeaconStateEip8321;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.BeaconStateSchemaEip8321;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.gloas.BeaconStateGloas;
import tech.pegasys.teku.spec.logic.common.forktransition.StateUpgrade;
import tech.pegasys.teku.spec.logic.versions.gloas.helpers.BeaconStateAccessorsGloas;
import tech.pegasys.teku.spec.schemas.SchemaDefinitionsEip8321;
import tech.pegasys.teku.spec.schemas.SchemaDefinitionsHeze;

import java.util.List;
import java.util.stream.IntStream;

public class Eip8321StateUpgrade implements StateUpgrade<BeaconStateEip8321> {

  private final SpecConfigEip8321 specConfig;
  private final SchemaDefinitionsEip8321 schemaDefinitions;
  private final BeaconStateAccessorsGloas beaconStateAccessors;

  public Eip8321StateUpgrade(
      final SpecConfigEip8321 specConfig,
      final SchemaDefinitionsEip8321 schemaDefinitions,
      final BeaconStateAccessorsGloas beaconStateAccessors) {
    this.specConfig = specConfig;
    this.schemaDefinitions = schemaDefinitions;
    this.beaconStateAccessors = beaconStateAccessors;
  }

  @Override
  public BeaconStateEip8321 upgrade(final BeaconState preState) {
    final UInt64 epoch = beaconStateAccessors.getCurrentEpoch(preState);
    final BeaconStateGloas preStateGloas = BeaconStateGloas.required(preState);
    final BeaconStateSchemaEip8321 targetStateSchema =
            BeaconStateSchemaEip8321.required(schemaDefinitions.getBeaconStateSchema());

    final List<SszBytes32> zeroCommitments =
            IntStream.range(0, preState.getValidators().size())
                    .mapToObj(__ -> SszBytes32.of(Bytes32.ZERO))
                    .toList();

    return targetStateSchema.createEmptyWithTransitionCachesFrom(preState)
        .updatedEip8321(
            state -> {
              BeaconStateFields.copyCommonFieldsFromSource(state, preState);

              state.setFork(
                  new Fork(
                      preState.getFork().getCurrentVersion(),
                      specConfig.getEip8321ForkVersion(),
                      epoch));

              state.setPreviousEpochParticipation(preStateGloas.getPreviousEpochParticipation());
              state.setCurrentEpochParticipation(preStateGloas.getCurrentEpochParticipation());
              state.setInactivityScores(preStateGloas.getInactivityScores());
              state.setCurrentSyncCommittee(preStateGloas.getCurrentSyncCommittee());
              state.setNextSyncCommittee(preStateGloas.getNextSyncCommittee());

              state.setLatestBlockHash(preStateGloas.getLatestBlockHash());
              state.setNextWithdrawalIndex(preStateGloas.getNextWithdrawalIndex());
              state.setNextWithdrawalValidatorIndex(
                  preStateGloas.getNextWithdrawalValidatorIndex());
              state.setHistoricalSummaries(preStateGloas.getHistoricalSummaries());
              state.setDepositRequestsStartIndex(preStateGloas.getDepositRequestsStartIndex());
              state.setDepositBalanceToConsume(preStateGloas.getDepositBalanceToConsume());
              state.setExitBalanceToConsume(preStateGloas.getExitBalanceToConsume());
              state.setEarliestExitEpoch(preStateGloas.getEarliestExitEpoch());
              state.setConsolidationBalanceToConsume(
                  preStateGloas.getConsolidationBalanceToConsume());
              state.setEarliestConsolidationEpoch(preStateGloas.getEarliestConsolidationEpoch());
              state.setPendingDeposits(preStateGloas.getPendingDeposits());
              state.setPendingPartialWithdrawals(preStateGloas.getPendingPartialWithdrawals());
              state.setPendingConsolidations(preStateGloas.getPendingConsolidations());
              state.setProposerLookahead(preStateGloas.getProposerLookahead());
              state.setBuilders(preStateGloas.getBuilders());
              state.setNextWithdrawalBuilderIndex(preStateGloas.getNextWithdrawalBuilderIndex());
              state.setExecutionPayloadAvailability(
                  preStateGloas.getExecutionPayloadAvailability());
              state.setBuilderPendingPayments(preStateGloas.getBuilderPendingPayments());
              state.setBuilderPendingWithdrawals(preStateGloas.getBuilderPendingWithdrawals());
              state.setLatestExecutionPayloadBid(preStateGloas.getLatestExecutionPayloadBid());
              state.setPayloadExpectedWithdrawals(preStateGloas.getPayloadExpectedWithdrawals());
              state.setPtcWindow(preStateGloas.getPtcWindow());
              state.setRandaoCommitments(
                      targetStateSchema
                              .getRandaoCommitmentsSchema()
                              .createFromElements(zeroCommitments));
              state.setPendingRandaoCommitments(targetStateSchema.getPendingRandaoCommitmentsSchema().of());
            });
  }
}
