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
import tech.pegasys.teku.spec.datastructures.state.Fork;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.common.BeaconStateFields;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.BeaconStateEip8321;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.BeaconStateSchemaEip8321;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.gloas.BeaconStateGloas;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.heze.BeaconStateHeze;
import tech.pegasys.teku.spec.logic.common.forktransition.StateUpgrade;
import tech.pegasys.teku.spec.logic.versions.gloas.helpers.BeaconStateAccessorsGloas;
import tech.pegasys.teku.spec.schemas.SchemaDefinitionsEip8321;

import java.util.List;
import java.util.stream.IntStream;

import static com.google.common.base.Preconditions.checkArgument;

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
    checkArgument(
            preState instanceof BeaconStateHeze,
            "Expected a Heze state before EIP-8321 but got %s",
            preState.getClass().getSimpleName());
    final BeaconStateHeze preStateHeze = (BeaconStateHeze) preState;
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

              state.setPreviousEpochParticipation(preStateHeze.getPreviousEpochParticipation());
              state.setCurrentEpochParticipation(preStateHeze.getCurrentEpochParticipation());
              state.setInactivityScores(preStateHeze.getInactivityScores());
              state.setCurrentSyncCommittee(preStateHeze.getCurrentSyncCommittee());
              state.setNextSyncCommittee(preStateHeze.getNextSyncCommittee());

              state.setLatestBlockHash(preStateHeze.getLatestBlockHash());
              state.setNextWithdrawalIndex(preStateHeze.getNextWithdrawalIndex());
              state.setNextWithdrawalValidatorIndex(
                  preStateHeze.getNextWithdrawalValidatorIndex());
              state.setHistoricalSummaries(preStateHeze.getHistoricalSummaries());
              state.setDepositBalanceToConsume(preStateHeze.getDepositBalanceToConsume());
              state.setExitBalanceToConsume(preStateHeze.getExitBalanceToConsume());
              state.setEarliestExitEpoch(preStateHeze.getEarliestExitEpoch());
              state.setConsolidationBalanceToConsume(
                  preStateHeze.getConsolidationBalanceToConsume());
              state.setEarliestConsolidationEpoch(preStateHeze.getEarliestConsolidationEpoch());
              state.setPendingDeposits(preStateHeze.getPendingDeposits());
              state.setPendingPartialWithdrawals(preStateHeze.getPendingPartialWithdrawals());
              state.setPendingConsolidations(preStateHeze.getPendingConsolidations());
              state.setProposerLookahead(preStateHeze.getProposerLookahead());
              state.setBuilders(preStateHeze.getBuilders());
              state.setNextWithdrawalBuilderIndex(preStateHeze.getNextWithdrawalBuilderIndex());
              state.setExecutionPayloadAvailability(
                  preStateHeze.getExecutionPayloadAvailability());
              state.setBuilderPendingPayments(preStateHeze.getBuilderPendingPayments());
              state.setBuilderPendingWithdrawals(preStateHeze.getBuilderPendingWithdrawals());
              state.setLatestExecutionPayloadBid(preStateHeze.getLatestExecutionPayloadBid());
              state.setPayloadExpectedWithdrawals(preStateHeze.getPayloadExpectedWithdrawals());
              state.setPtcWindow(preStateHeze.getPtcWindow());
              state.setRandaoCommitments(
                      targetStateSchema
                              .getRandaoCommitmentsSchema()
                              .createFromElements(zeroCommitments));
              state.setPendingRandaoCommitments(targetStateSchema.getPendingRandaoCommitmentsSchema().of());
            });
  }
}
