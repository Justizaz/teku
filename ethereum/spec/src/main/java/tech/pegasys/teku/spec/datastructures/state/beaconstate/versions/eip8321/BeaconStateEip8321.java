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
import tech.pegasys.teku.infrastructure.ssz.SszCollection;
import tech.pegasys.teku.infrastructure.ssz.SszData;
import tech.pegasys.teku.infrastructure.ssz.SszList;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszBytes32;
import tech.pegasys.teku.spec.datastructures.operations.PendingRandaoCommitment;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.gloas.BeaconStateGloas;

import java.util.Optional;

public interface BeaconStateEip8321 extends BeaconStateGloas {
  static BeaconStateEip8321 required(final BeaconState state) {
    return state
        .toVersionEip8321()
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    "Expected a Eip8321 state but got: " + state.getClass().getSimpleName()));
  }

  @SuppressWarnings("unused")
  private static <T extends SszData> void addItems(
      final MoreObjects.ToStringHelper stringBuilder,
      final String keyPrefix,
      final SszCollection<T> items) {
    for (int i = 0; i < items.size(); i++) {
      stringBuilder.add(keyPrefix + "[" + i + "]", items.get(i));
    }
  }

  static void describeCustomEip8321Fields(
      final MoreObjects.ToStringHelper stringBuilder, final BeaconStateEip8321 state) {
    BeaconStateGloas.describeCustomGloasFields(stringBuilder, state);
    stringBuilder.add("randao_commitments", state.getRandaoCommitments());
    stringBuilder.add("pending_randao_commitments", state.getPendingRandaoCommitments());
  }

  @Override
  MutableBeaconStateEip8321 createWritableCopy();

  default <E1 extends Exception, E2 extends Exception, E3 extends Exception>
  BeaconStateEip8321 updatedEip8321(final Mutator<MutableBeaconStateEip8321, E1, E2, E3> mutator)
          throws E1, E2, E3 {
    MutableBeaconStateEip8321 writableCopy = createWritableCopy();
    mutator.mutate(writableCopy);
    return writableCopy.commitChanges();
  }

  @Override
  default Optional<BeaconStateEip8321> toVersionEip8321() {
    return Optional.of(this);
  }


  SszList<SszBytes32> getRandaoCommitments();

  SszList<PendingRandaoCommitment> getPendingRandaoCommitments();
}
