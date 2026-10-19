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

import tech.pegasys.teku.infrastructure.ssz.SszList;
import tech.pegasys.teku.infrastructure.ssz.SszMutableList;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszBytes32;
import tech.pegasys.teku.spec.datastructures.operations.PendingRandaoCommitment;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.MutableBeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.common.BeaconStateFields;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.gloas.MutableBeaconStateGloas;
import tech.pegasys.teku.spec.datastructures.state.versions.gloas.Builder;

import java.util.Optional;

public interface MutableBeaconStateEip8321 extends MutableBeaconStateGloas, BeaconStateEip8321 {
  static MutableBeaconStateEip8321 required(final MutableBeaconState state) {
    return state
        .toMutableVersionEip8321()
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    "Expected a Eip8321 state but got: " + state.getClass().getSimpleName()));
  }

  @Override
  BeaconStateEip8321 commitChanges();

  @Override
  default Optional<MutableBeaconStateEip8321> toMutableVersionEip8321() {
    return Optional.of(this);
  }

  SszMutableList<SszBytes32> getRandaoCommitments();

  void setRandaoCommitments(SszList<SszBytes32> randaoCommitments);

  SszMutableList<PendingRandaoCommitment> getPendingRandaoCommitments();

  void setPendingRandaoCommitments(SszList<PendingRandaoCommitment> pendingRandaoCommitments);
}
