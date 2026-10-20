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

package tech.pegasys.teku.spec.datastructures.blocks.blockbody.versions.eip8321;

import java.util.Optional;

import org.apache.tuweni.bytes.Bytes32;
import tech.pegasys.teku.infrastructure.ssz.SszList;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszBytes32;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.BeaconBlockBody;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.versions.electra.BeaconBlockBodyElectra;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.versions.gloas.BeaconBlockBodyGloas;
import tech.pegasys.teku.spec.datastructures.operations.SignedRandaoCommitmentRegistration;

public interface BeaconBlockBodyEip8321 extends BeaconBlockBodyGloas {

    static BeaconBlockBodyEip8321 required(final BeaconBlockBody body) {
        if (body instanceof BeaconBlockBodyEip8321) {
            return (BeaconBlockBodyEip8321) body;
        }
        throw new IllegalArgumentException(
                "Expected Eip8321 block body but got " + body.getClass().getSimpleName());
    }

    Bytes32 getHashChainReveal();

    SszBytes32 getHashChainRevealSsz();

    SszList<SignedRandaoCommitmentRegistration> getRandaoCommitmentRegistrations();

    @Override
    BeaconBlockBodySchemaEip8321<?> getSchema();

    default Optional<BeaconBlockBodyEip8321> toVersionEip8321() {
        return Optional.of(this);
    }
}