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
import tech.pegasys.teku.infrastructure.ssz.SszData;
import tech.pegasys.teku.infrastructure.ssz.SszList;
import tech.pegasys.teku.infrastructure.ssz.SszMutableList;
import tech.pegasys.teku.infrastructure.ssz.cache.IntCache;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszBytes32;
import tech.pegasys.teku.infrastructure.ssz.tree.TreeNode;
import tech.pegasys.teku.spec.datastructures.operations.PendingRandaoCommitment;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconStateCache;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.common.AbstractMutableBeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.common.SlotCaches;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.common.TransitionCaches;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.altair.ValidatorStatsAltair;

public class MutableBeaconStateEip8321Impl extends AbstractMutableBeaconState<BeaconStateEip8321Impl>
    implements MutableBeaconStateEip8321, BeaconStateCache, ValidatorStatsAltair {

  MutableBeaconStateEip8321Impl(final BeaconStateEip8321Impl backingImmutableView) {
    super(backingImmutableView);
  }

  MutableBeaconStateEip8321Impl(
      final BeaconStateEip8321Impl backingImmutableView, final boolean builder) {
    super(backingImmutableView, builder);
  }

  @Override
  protected BeaconStateEip8321Impl createImmutableBeaconState(
      final TreeNode backingNode,
      final IntCache<SszData> viewCache,
      final TransitionCaches transitionCaches,
      final SlotCaches slotCaches) {
    return new BeaconStateEip8321Impl(
        getSchema(), backingNode, viewCache, transitionCaches, slotCaches);
  }

  @Override
  protected void addCustomFields(final MoreObjects.ToStringHelper stringBuilder) {
    BeaconStateEip8321.describeCustomEip8321Fields(stringBuilder, this);
  }

  @Override
  public BeaconStateEip8321 commitChanges() {
    return (BeaconStateEip8321) super.commitChanges();
  }

  @Override
  public SszMutableList<SszBytes32> getRandaoCommitments() {
    final int index = getSchema().getFieldIndex("randao_commitments");
    return getAnyByRef(index);
  }

  @Override
  public void setRandaoCommitments(final SszList<SszBytes32> randaoCommitments) {
    final int index = getSchema().getFieldIndex("randao_commitments");
    set(index, randaoCommitments);
  }

  @Override
  public SszMutableList<PendingRandaoCommitment> getPendingRandaoCommitments() {
    final int index = getSchema().getFieldIndex("pending_randao_commitments");
    return getAnyByRef(index);
  }

  @Override
  public void setPendingRandaoCommitments(final SszList<PendingRandaoCommitment> pendingRandaoCommitments) {
    final int index = getSchema().getFieldIndex("pending_randao_commitments");
    set(index, pendingRandaoCommitments);
  }

  @Override
  public MutableBeaconStateEip8321 createWritableCopy() {
    return (MutableBeaconStateEip8321) super.createWritableCopy();
  }
}
