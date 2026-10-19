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
import tech.pegasys.teku.infrastructure.ssz.primitive.SszBytes32;
import tech.pegasys.teku.spec.datastructures.operations.PendingRandaoCommitment;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.electra.MutableBeaconStateElectra;

public interface MutableBeaconStateEip8321
        extends BeaconStateEip8321, MutableBeaconStateElectra {

    static MutableBeaconStateEip8321 required(final Object state) {
        if (state instanceof MutableBeaconStateEip8321) {
            return (MutableBeaconStateEip8321) state;
        }
        throw new IllegalArgumentException(
                "Expected MutableEip8321 state but got " + state.getClass().getSimpleName());
    }

    void setRandaoCommitments(SszList<SszBytes32> randaoCommitments);

    void setPendingRandaoCommitments(SszList<PendingRandaoCommitment> pendingRandaoCommitments);
}