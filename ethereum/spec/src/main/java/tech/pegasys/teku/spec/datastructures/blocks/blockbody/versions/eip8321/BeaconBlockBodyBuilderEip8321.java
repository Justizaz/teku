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

import static com.google.common.base.Preconditions.checkNotNull;

import tech.pegasys.teku.infrastructure.ssz.SszList;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszBytes32;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.BeaconBlockBody;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.BeaconBlockBodyBuilder;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.BeaconBlockBodySchema;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.versions.electra.BeaconBlockBodyBuilderElectra;
import tech.pegasys.teku.spec.datastructures.execution.ExecutionRequests;
import tech.pegasys.teku.spec.datastructures.execution.versions.deneb.ExecutionPayloadDenebImpl;
import tech.pegasys.teku.spec.datastructures.operations.SignedRandaoCommitmentRegistration;
import tech.pegasys.teku.spec.datastructures.type.SszSignature;

public class BeaconBlockBodyBuilderEip8321 extends BeaconBlockBodyBuilderElectra {

    private ExecutionRequests executionRequests;
    private SszList<SignedRandaoCommitmentRegistration> randaoCommitmentRegistrations;

    @SuppressWarnings({"rawtypes", "unchecked"})
    public BeaconBlockBodyBuilderEip8321(
            final BeaconBlockBodySchema<?> schema,
            final BeaconBlockBodySchema<?> blindedSchema) {
        super((BeaconBlockBodySchema) schema, (BeaconBlockBodySchema) blindedSchema);
    }

    @Override
    public BeaconBlockBodyBuilder executionRequests(final ExecutionRequests executionRequests) {
        this.executionRequests = executionRequests;
        super.executionRequests(executionRequests);
        return this;
    }

    public BeaconBlockBodyBuilderEip8321 randaoCommitmentRegistrations(
            final SszList<SignedRandaoCommitmentRegistration> randaoCommitmentRegistrations) {
        this.randaoCommitmentRegistrations = randaoCommitmentRegistrations;
        return this;
    }

    @Override
    protected void validate() {
        super.validate();
        checkNotNull(executionRequests, "execution_requests must be specified");
        checkNotNull(randaoCommitmentRegistrations, "randao_commitment_registrations must be specified");
    }

    @Override
    public BeaconBlockBody build() {
        validate();
        final BeaconBlockBodySchemaEip8321Impl schema =
                getAndValidateSchema(false, BeaconBlockBodySchemaEip8321Impl.class);
        return new BeaconBlockBodyEip8321Impl(
                schema,
                new SszSignature(randaoReveal),
                eth1Data,
                SszBytes32.of(graffiti),
                proposerSlashings,
                attesterSlashings,
                attestations,
                deposits,
                voluntaryExits,
                syncAggregate,
                (ExecutionPayloadDenebImpl) executionPayload.toVersionDeneb().orElseThrow(),
                getBlsToExecutionChanges(),
                getBlobKzgCommitments(),
                executionRequests,
                randaoCommitmentRegistrations);
    }
}