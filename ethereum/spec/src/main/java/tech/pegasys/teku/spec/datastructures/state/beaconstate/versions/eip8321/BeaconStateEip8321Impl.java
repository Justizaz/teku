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

import com.google.common.base.MoreObjects;
import tech.pegasys.teku.infrastructure.ssz.SszContainer;
import tech.pegasys.teku.infrastructure.ssz.SszData;
import tech.pegasys.teku.infrastructure.ssz.SszList;
import tech.pegasys.teku.infrastructure.ssz.cache.IntCache;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszBytes32;
import tech.pegasys.teku.infrastructure.ssz.schema.SszCompositeSchema;
import tech.pegasys.teku.infrastructure.ssz.schema.impl.AbstractSszContainerSchema;
import tech.pegasys.teku.infrastructure.ssz.tree.TreeNode;
import tech.pegasys.teku.spec.datastructures.operations.PendingRandaoCommitment;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconStateCache;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconStateSchema;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.common.AbstractBeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.common.SlotCaches;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.common.TransitionCaches;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.altair.ValidatorStatsAltair;

public class BeaconStateEip8321Impl extends AbstractBeaconState<MutableBeaconStateEip8321>
    implements BeaconStateEip8321, BeaconStateCache, ValidatorStatsAltair {

  BeaconStateEip8321Impl(final BeaconStateSchema<BeaconStateEip8321, MutableBeaconStateEip8321> schema) {
    super(schema);
  }

  BeaconStateEip8321Impl(
      final BeaconStateSchema<BeaconStateEip8321, MutableBeaconStateEip8321> schema,
      final TransitionCaches transitionCaches,
      final SlotCaches slotCaches) {
    super(schema, schema.getDefaultTree(), null, transitionCaches, slotCaches);
  }

  BeaconStateEip8321Impl(
      final SszCompositeSchema<?> type,
      final TreeNode backingNode,
      final IntCache<SszData> cache,
      final TransitionCaches transitionCaches,
      final SlotCaches slotCaches) {
    super(type, backingNode, cache, transitionCaches, slotCaches);
  }

  BeaconStateEip8321Impl(
      final AbstractSszContainerSchema<? extends SszContainer> type, final TreeNode backingNode) {
    super(type, backingNode);
  }

  @Override
  public BeaconStateSchemaEip8321 getBeaconStateSchema() {
    return (BeaconStateSchemaEip8321) getSchema();
  }

  @Override
  public MutableBeaconStateEip8321 createWritableCopy() {
    return new MutableBeaconStateEip8321Impl(this);
  }

  @Override
  public SszList<SszBytes32> getRandaoCommitments() {
    final int index = getSchema().getFieldIndex("randao_commitments");
    return getAny(index);
  }

  @Override
  public SszList<PendingRandaoCommitment> getPendingRandaoCommitments() {
    final int index = getSchema().getFieldIndex("pending_randao_commitments");
    return getAny(index);
  }

  @Override
  protected void describeCustomFields(final MoreObjects.ToStringHelper stringBuilder) {
    BeaconStateEip8321.describeCustomEip8321Fields(stringBuilder, this);
  }
}
