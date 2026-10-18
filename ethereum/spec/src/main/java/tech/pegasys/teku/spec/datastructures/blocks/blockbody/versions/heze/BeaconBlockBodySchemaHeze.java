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

package tech.pegasys.teku.spec.datastructures.blocks.blockbody.versions.heze;

import static com.google.common.base.Preconditions.checkArgument;

import tech.pegasys.teku.infrastructure.ssz.schema.SszListSchema;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.BeaconBlockBodySchema;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.versions.gloas.BeaconBlockBodySchemaGloas;
import tech.pegasys.teku.spec.datastructures.operations.RandaoCommitmentRegistration;

public interface BeaconBlockBodySchemaHeze<T extends BeaconBlockBodyHeze>
        extends BeaconBlockBodySchemaGloas<T> {

    static BeaconBlockBodySchemaHeze<?> required(final BeaconBlockBodySchema<?> schema) {
        checkArgument(
                schema instanceof BeaconBlockBodySchemaHeze<?>,
                "Expected a BeaconBlockBodySchemaHeze but was %s",
                schema.getClass());
        return (BeaconBlockBodySchemaHeze<?>) schema;
    }

    SszListSchema<RandaoCommitmentRegistration, ?> getRandaoCommitmentRegistrationsSchema();
}