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

import static com.google.common.base.Preconditions.checkNotNull;

import tech.pegasys.teku.infrastructure.ssz.SszList;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszBytes32;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.BeaconBlockBody;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.BeaconBlockBodyBuilder;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.BeaconBlockBodySchema;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.versions.gloas.BeaconBlockBodyBuilderGloas;
import tech.pegasys.teku.spec.datastructures.epbs.versions.gloas.PayloadAttestation;
import tech.pegasys.teku.spec.datastructures.epbs.versions.gloas.SignedExecutionPayloadBid;
import tech.pegasys.teku.spec.datastructures.execution.ExecutionRequests;
import tech.pegasys.teku.spec.datastructures.operations.RandaoCommitmentRegistration;
import tech.pegasys.teku.spec.datastructures.type.SszSignature;

public class BeaconBlockBodyBuilderHeze extends BeaconBlockBodyBuilderGloas {

    private SignedExecutionPayloadBid signedExecutionPayloadBid;
    private SszList<PayloadAttestation> payloadAttestations;
    private ExecutionRequests parentExecutionRequests;
    private SszList<RandaoCommitmentRegistration> randaoCommitmentRegistrations;

    public BeaconBlockBodyBuilderHeze(
            final BeaconBlockBodySchema<? extends BeaconBlockBodyHeze> schema) {
        super(schema);
    }

    @Override
    public BeaconBlockBodyBuilder signedExecutionPayloadBid(
            final SignedExecutionPayloadBid signedExecutionPayloadBid) {
        super.signedExecutionPayloadBid(signedExecutionPayloadBid);
        this.signedExecutionPayloadBid = signedExecutionPayloadBid;
        return this;
    }

    @Override
    public BeaconBlockBodyBuilder payloadAttestations(
            final SszList<PayloadAttestation> payloadAttestations) {
        super.payloadAttestations(payloadAttestations);
        this.payloadAttestations = payloadAttestations;
        return this;
    }

    @Override
    public BeaconBlockBodyBuilder parentExecutionRequests(
            final ExecutionRequests parentExecutionRequests) {
        super.parentExecutionRequests(parentExecutionRequests);
        this.parentExecutionRequests = parentExecutionRequests;
        return this;
    }

    public Boolean supportsRandaoCommitmentRegistrations() {
        return true;
    }

    public BeaconBlockBodyBuilder randaoCommitmentRegistrations(
            final SszList<RandaoCommitmentRegistration> randaoCommitmentRegistrations) {
        this.randaoCommitmentRegistrations = randaoCommitmentRegistrations;
        return this;
    }

    @Override
    protected void validate() {
        super.validate();
        checkNotNull(
                randaoCommitmentRegistrations, "randaoCommitmentRegistrations must be specified");
    }

    @Override
    public BeaconBlockBody build() {
        validate();
        final BeaconBlockBodySchemaHezeImpl schema =
                getAndValidateSchema(false, BeaconBlockBodySchemaHezeImpl.class);
        return new BeaconBlockBodyHezeImpl(
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
                getBlsToExecutionChanges(),
                signedExecutionPayloadBid,
                payloadAttestations,
                parentExecutionRequests,
                randaoCommitmentRegistrations);
    }
}