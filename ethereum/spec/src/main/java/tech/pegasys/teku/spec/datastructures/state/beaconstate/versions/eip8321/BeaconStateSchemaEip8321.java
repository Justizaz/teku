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

package tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321;

import com.google.common.annotations.VisibleForTesting;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszByte;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszBytes32;
import tech.pegasys.teku.infrastructure.ssz.schema.*;
import tech.pegasys.teku.infrastructure.ssz.schema.collections.SszBitvectorSchema;
import tech.pegasys.teku.infrastructure.ssz.schema.collections.SszPrimitiveListSchema;
import tech.pegasys.teku.infrastructure.ssz.schema.collections.SszUInt64ListSchema;
import tech.pegasys.teku.infrastructure.ssz.schema.collections.SszUInt64VectorSchema;
import tech.pegasys.teku.infrastructure.ssz.sos.SszField;
import tech.pegasys.teku.infrastructure.ssz.tree.TreeNode;
import tech.pegasys.teku.spec.config.SpecConfig;
import tech.pegasys.teku.spec.datastructures.execution.versions.capella.Withdrawal;
import tech.pegasys.teku.spec.datastructures.operations.PendingRandaoCommitment;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconStateCache;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconStateSchema;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.common.AbstractBeaconStateSchema;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.common.BeaconStateFields;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.common.SlotCaches;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.gloas.*;
import tech.pegasys.teku.spec.datastructures.state.versions.electra.PendingConsolidation;
import tech.pegasys.teku.spec.datastructures.state.versions.electra.PendingDeposit;
import tech.pegasys.teku.spec.datastructures.state.versions.electra.PendingPartialWithdrawal;
import tech.pegasys.teku.spec.datastructures.state.versions.gloas.Builder;
import tech.pegasys.teku.spec.datastructures.state.versions.gloas.BuilderPendingPayment;
import tech.pegasys.teku.spec.datastructures.state.versions.gloas.BuilderPendingWithdrawal;
import tech.pegasys.teku.spec.datastructures.state.versions.gloas.PayloadTimelinessCommitteeWindowSchema;
import tech.pegasys.teku.spec.schemas.registry.SchemaRegistry;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.google.common.base.Preconditions.checkArgument;

public class BeaconStateSchemaEip8321
    extends AbstractBeaconStateSchema<BeaconStateEip8321, MutableBeaconStateEip8321> {

  public static final int RANDAO_COMMITMENTS_FIELD_INDEX = 46;
  public static final int PENDING_RANDAO_COMMITMENTS_FIELD_INDEX = 47;

  private static final boolean[] ACTIVE_FIELDS =
      ProgressiveSchemaUtils.allActive(PENDING_RANDAO_COMMITMENTS_FIELD_INDEX + 1);

  private static final Set<String> PROGRESSIVE_INLINE_LIST_FIELD_NAMES =
      Stream.of(
              BeaconStateFields.PREVIOUS_EPOCH_PARTICIPATION,
              BeaconStateFields.CURRENT_EPOCH_PARTICIPATION,
              BeaconStateFields.INACTIVITY_SCORES,
              BeaconStateFields.BUILDERS)
          .map(BeaconStateFields::getSszFieldName)
          .collect(Collectors.toSet());

  @VisibleForTesting
  BeaconStateSchemaEip8321(final SpecConfig specConfig, final SchemaRegistry schemaRegistry) {
    super(
        "BeaconStateEip8321", ACTIVE_FIELDS, getUniqueFields(specConfig, schemaRegistry), specConfig);
  }

  private static SszField toProgressiveListFieldIfListed(final SszField field) {
    if (!PROGRESSIVE_INLINE_LIST_FIELD_NAMES.contains(field.getName())) {
      return field;
    }
    final SszSchema<?> progressiveSchema =
        BeaconStateFields.toProgressiveListSchema((SszListSchema<?, ?>) field.getSchema().get());
    return new SszField(field.getIndex(), field.getName(), () -> progressiveSchema);
  }

  private static List<SszField> getUniqueFields(
      final SpecConfig specConfig, final SchemaRegistry schemaRegistry) {
    return Stream.concat(
            BeaconStateSchemaGloas.getUniqueFields(specConfig, schemaRegistry).stream(),
            Stream.of(
                new SszField(
                    RANDAO_COMMITMENTS_FIELD_INDEX,
                    "randao_commitments",
                    () ->
                        SszListSchema.create(
                            SszPrimitiveSchemas.BYTES32_SCHEMA,
                            specConfig.getValidatorRegistryLimit())),
                new SszField(
                    PENDING_RANDAO_COMMITMENTS_FIELD_INDEX,
                    "pending_randao_commitments",
                    () -> SszProgressiveListSchema.create(PendingRandaoCommitment.SSZ_SCHEMA))))
            .toList();
  }

  @SuppressWarnings("unchecked")
  public SszPrimitiveListSchema<Byte, SszByte, ?> getPreviousEpochParticipationSchema() {
    return (SszPrimitiveListSchema<Byte, SszByte, ?>)
        getChildSchema(getFieldIndex(BeaconStateFields.PREVIOUS_EPOCH_PARTICIPATION));
  }

  @SuppressWarnings("unchecked")
  public SszPrimitiveListSchema<Byte, SszByte, ?> getCurrentEpochParticipationSchema() {
    return (SszPrimitiveListSchema<Byte, SszByte, ?>)
        getChildSchema(getFieldIndex(BeaconStateFields.CURRENT_EPOCH_PARTICIPATION));
  }

  public SszUInt64ListSchema<?> getInactivityScoresSchema() {
    return (SszUInt64ListSchema<?>)
        getChildSchema(getFieldIndex(BeaconStateFields.INACTIVITY_SCORES));
  }

  @SuppressWarnings("unchecked")
  public SszListSchema<PendingDeposit, ?> getPendingDepositsSchema() {
    return (SszListSchema<PendingDeposit, ?>)
        getChildSchema(getFieldIndex(BeaconStateFields.PENDING_DEPOSITS));
  }

  public SszUInt64VectorSchema<?> getProposerLookaheadSchema() {
    return (SszUInt64VectorSchema<?>)
        getChildSchema(getFieldIndex(BeaconStateFields.PROPOSER_LOOKAHEAD));
  }

  @SuppressWarnings("unchecked")
  public SszListSchema<Builder, ?> getBuildersSchema() {
    return (SszListSchema<Builder, ?>) getChildSchema(getFieldIndex(BeaconStateFields.BUILDERS));
  }

  @SuppressWarnings("unchecked")
  public SszListSchema<SszBytes32, ?> getRandaoCommitmentsSchema() {
    return (SszListSchema<SszBytes32, ?>) getChildSchema(getFieldIndex("randao_commitments"));
  }

  @SuppressWarnings("unchecked")
  public SszListSchema<PendingRandaoCommitment, ?> getPendingRandaoCommitmentsSchema() {
    return (SszListSchema<PendingRandaoCommitment, ?>) getChildSchema(getFieldIndex("pending_randao_commitments"));
  }

  @Override
  public MutableBeaconStateEip8321 createBuilder() {
    return new MutableBeaconStateEip8321Impl(createEmptyBeaconStateImpl(), true);
  }

  public static BeaconStateSchemaEip8321 create(
      final SpecConfig specConfig, final SchemaRegistry schemaRegistry) {
    return new BeaconStateSchemaEip8321(specConfig, schemaRegistry);
  }

  public static BeaconStateSchemaEip8321 required(final BeaconStateSchema<?, ?> schema) {
    checkArgument(
        schema instanceof BeaconStateSchemaEip8321,
        "Expected a BeaconStateSchemaEip8321 but was %s",
        schema.getClass());
    return (BeaconStateSchemaEip8321) schema;
  }

  @Override
  public BeaconStateEip8321 createEmpty() {
    return createEmptyBeaconStateImpl();
  }

  public BeaconStateEip8321 createEmptyWithTransitionCachesFrom(final BeaconState sourceState) {
    return new BeaconStateEip8321Impl(
        this,
        BeaconStateCache.getTransitionCaches(sourceState).copy(),
        SlotCaches.createNewEmpty());
  }

  private BeaconStateEip8321Impl createEmptyBeaconStateImpl() {
    return new BeaconStateEip8321Impl(this);
  }

  @Override
  public BeaconStateEip8321Impl createFromBackingNode(final TreeNode node) {
    return new BeaconStateEip8321Impl(this, node);
  }
}
