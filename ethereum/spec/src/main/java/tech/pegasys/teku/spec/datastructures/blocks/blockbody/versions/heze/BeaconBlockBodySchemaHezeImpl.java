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

import static tech.pegasys.teku.spec.schemas.registry.SchemaTypes.ATTESTATION_SCHEMA;
import static tech.pegasys.teku.spec.schemas.registry.SchemaTypes.EXECUTION_REQUESTS_SCHEMA;
import static tech.pegasys.teku.spec.schemas.registry.SchemaTypes.PAYLOAD_ATTESTATION_SCHEMA;
import static tech.pegasys.teku.spec.schemas.registry.SchemaTypes.SIGNED_BLS_TO_EXECUTION_CHANGE_SCHEMA;
import static tech.pegasys.teku.spec.schemas.registry.SchemaTypes.SIGNED_EXECUTION_PAYLOAD_BID_SCHEMA;

import it.unimi.dsi.fastutil.longs.LongList;
import tech.pegasys.teku.infrastructure.async.SafeFuture;
import tech.pegasys.teku.infrastructure.ssz.SszList;
import tech.pegasys.teku.infrastructure.ssz.containers.ContainerSchema14;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszBytes32;
import tech.pegasys.teku.infrastructure.ssz.schema.ProgressiveSchemaUtils;
import tech.pegasys.teku.infrastructure.ssz.schema.SszListSchema;
import tech.pegasys.teku.infrastructure.ssz.schema.SszPrimitiveSchemas;
import tech.pegasys.teku.infrastructure.ssz.schema.SszProgressiveListSchema;
import tech.pegasys.teku.infrastructure.ssz.schema.SszSchema;
import tech.pegasys.teku.infrastructure.ssz.tree.TreeNode;
import tech.pegasys.teku.spec.config.SpecConfigHeze;
import tech.pegasys.teku.spec.datastructures.blocks.Eth1Data;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.BeaconBlockBody;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.BeaconBlockBodyBuilder;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.common.BlockBodyFields;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.versions.altair.SyncAggregate;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.versions.altair.SyncAggregateSchema;
import tech.pegasys.teku.spec.datastructures.epbs.versions.gloas.PayloadAttestation;
import tech.pegasys.teku.spec.datastructures.epbs.versions.gloas.SignedExecutionPayloadBid;
import tech.pegasys.teku.spec.datastructures.execution.ExecutionPayloadSchema;
import tech.pegasys.teku.spec.datastructures.execution.ExecutionRequests;
import tech.pegasys.teku.spec.datastructures.execution.ExecutionRequestsSchema;
import tech.pegasys.teku.spec.datastructures.operations.Attestation;
import tech.pegasys.teku.spec.datastructures.operations.AttesterSlashing;
import tech.pegasys.teku.spec.datastructures.operations.Deposit;
import tech.pegasys.teku.spec.datastructures.operations.ProposerSlashing;
import tech.pegasys.teku.spec.datastructures.operations.RandaoCommitmentRegistration;
import tech.pegasys.teku.spec.datastructures.operations.SignedBlsToExecutionChange;
import tech.pegasys.teku.spec.datastructures.operations.SignedVoluntaryExit;
import tech.pegasys.teku.spec.datastructures.type.SszKZGCommitment;
import tech.pegasys.teku.spec.datastructures.type.SszSignature;
import tech.pegasys.teku.spec.datastructures.type.SszSignatureSchema;
import tech.pegasys.teku.spec.schemas.registry.SchemaRegistry;
import tech.pegasys.teku.spec.schemas.registry.SchemaTypes;

import java.util.function.Function;

public class BeaconBlockBodySchemaHezeImpl
        extends ContainerSchema14<
        BeaconBlockBodyHezeImpl,
        SszSignature,
        Eth1Data,
        SszBytes32,
        SszList<ProposerSlashing>,
        SszList<AttesterSlashing>,
        SszList<Attestation>,
        SszList<Deposit>,
        SszList<SignedVoluntaryExit>,
        SyncAggregate,
        SszList<SignedBlsToExecutionChange>,
        SignedExecutionPayloadBid,
        SszList<PayloadAttestation>,
        ExecutionRequests,
        SszList<RandaoCommitmentRegistration>>
        implements BeaconBlockBodySchemaHeze<BeaconBlockBodyHezeImpl> {

    private static final boolean[] ACTIVE_FIELDS = ProgressiveSchemaUtils.allActive(14);

    protected BeaconBlockBodySchemaHezeImpl(
            final String containerName,
            final NamedSchema<SszSignature> randaoRevealSchema,
            final NamedSchema<Eth1Data> eth1DataSchema,
            final NamedSchema<SszBytes32> graffitiSchema,
            final NamedSchema<SszList<ProposerSlashing>> proposerSlashingsSchema,
            final NamedSchema<SszList<AttesterSlashing>> attesterSlashingsSchema,
            final NamedSchema<SszList<Attestation>> attestationsSchema,
            final NamedSchema<SszList<Deposit>> depositsSchema,
            final NamedSchema<SszList<SignedVoluntaryExit>> voluntaryExitsSchema,
            final NamedSchema<SyncAggregate> syncAggregateSchema,
            final NamedSchema<SszList<SignedBlsToExecutionChange>> blsToExecutionChange,
            final NamedSchema<SignedExecutionPayloadBid> signedExecutionPayloadBid,
            final NamedSchema<SszList<PayloadAttestation>> payloadAttestations,
            final NamedSchema<ExecutionRequests> executionRequests,
            final NamedSchema<SszList<RandaoCommitmentRegistration>> randaoCommitmentRegistrations) {
        super(
                containerName,
                ACTIVE_FIELDS,
                randaoRevealSchema,
                eth1DataSchema,
                graffitiSchema,
                proposerSlashingsSchema,
                attesterSlashingsSchema,
                attestationsSchema,
                depositsSchema,
                voluntaryExitsSchema,
                syncAggregateSchema,
                blsToExecutionChange,
                signedExecutionPayloadBid,
                payloadAttestations,
                executionRequests,
                randaoCommitmentRegistrations);
    }

    public static BeaconBlockBodySchemaHezeImpl create(
            final SpecConfigHeze specConfig,
            final String containerName,
            final SchemaRegistry schemaRegistry) {
        return new BeaconBlockBodySchemaHezeImpl(
                containerName,
                namedSchema(BlockBodyFields.RANDAO_REVEAL, SszSignatureSchema.INSTANCE),
                namedSchema(BlockBodyFields.ETH1_DATA, Eth1Data.SSZ_SCHEMA),
                namedSchema(BlockBodyFields.GRAFFITI, SszPrimitiveSchemas.BYTES32_SCHEMA),
                namedSchema(
                        BlockBodyFields.PROPOSER_SLASHINGS,
                        SszProgressiveListSchema.create(
                                ProposerSlashing.SSZ_SCHEMA, specConfig.getMaxProposerSlashings())),
                namedSchema(
                        BlockBodyFields.ATTESTER_SLASHINGS,
                        SszProgressiveListSchema.create(
                                schemaRegistry.get(SchemaTypes.ATTESTER_SLASHING_SCHEMA),
                                specConfig.getMaxAttesterSlashingsElectra())),
                namedSchema(
                        BlockBodyFields.ATTESTATIONS,
                        SszProgressiveListSchema.create(
                                schemaRegistry.get(ATTESTATION_SCHEMA), specConfig.getMaxAttestationsElectra())),
                namedSchema(
                        BlockBodyFields.DEPOSITS,
                        SszProgressiveListSchema.create(Deposit.SSZ_SCHEMA, 0)),
                namedSchema(
                        BlockBodyFields.VOLUNTARY_EXITS,
                        SszProgressiveListSchema.create(
                                SignedVoluntaryExit.SSZ_SCHEMA, specConfig.getMaxVoluntaryExits())),
                namedSchema(
                        BlockBodyFields.SYNC_AGGREGATE,
                        SyncAggregateSchema.create(specConfig.getSyncCommitteeSize())),
                namedSchema(
                        BlockBodyFields.BLS_TO_EXECUTION_CHANGES,
                        SszProgressiveListSchema.create(
                                schemaRegistry.get(SIGNED_BLS_TO_EXECUTION_CHANGE_SCHEMA),
                                specConfig.getMaxBlsToExecutionChanges())),
                namedSchema(
                        BlockBodyFields.SIGNED_EXECUTION_PAYLOAD_BID,
                        schemaRegistry.get(SIGNED_EXECUTION_PAYLOAD_BID_SCHEMA)),
                namedSchema(
                        BlockBodyFields.PAYLOAD_ATTESTATIONS,
                        SszProgressiveListSchema.create(
                                schemaRegistry.get(PAYLOAD_ATTESTATION_SCHEMA),
                                specConfig.getMaxPayloadAttestations())),
                namedSchema(
                        BlockBodyFields.PARENT_EXECUTION_REQUESTS,
                        SszSchema.as(ExecutionRequests.class, schemaRegistry.get(EXECUTION_REQUESTS_SCHEMA))),
                namedSchema(
                        "randao_commitment_registrations",
                        SszProgressiveListSchema.create(
                                RandaoCommitmentRegistration.SSZ_SCHEMA,
                                specConfig.getMaxRandaoCommitmentRegistrationsPerBlock())));
    }

    @Override
    public SafeFuture<? extends BeaconBlockBody> createBlockBody(Function<BeaconBlockBodyBuilder, SafeFuture<Void>> bodyBuilder) {
        return null;
    }

    @Override
    public BeaconBlockBody createEmpty() {
        return null;
    }

    @Override
    public BeaconBlockBodyHezeImpl createFromBackingNode(final TreeNode node) {
        return new BeaconBlockBodyHezeImpl(this, node);
    }

    @Override
    public SszListSchema<ProposerSlashing, ?> getProposerSlashingsSchema() {
        return null;
    }

    @Override
    public SszListSchema<AttesterSlashing, ?> getAttesterSlashingsSchema() {
        return null;
    }

    @Override
    public SszListSchema<Attestation, ?> getAttestationsSchema() {
        return null;
    }

    @Override
    public SszListSchema<Deposit, ?> getDepositsSchema() {
        return null;
    }

    @Override
    public SszListSchema<SignedVoluntaryExit, ?> getVoluntaryExitsSchema() {
        return null;
    }

    @Override
    public LongList getBlindedNodeGeneralizedIndices() {
        return null;
    }

    @SuppressWarnings("unchecked")
    @Override
    public SszListSchema<RandaoCommitmentRegistration, ?> getRandaoCommitmentRegistrationsSchema() {
        return (SszListSchema<RandaoCommitmentRegistration, ?>)
                getChildSchema(getFieldIndex("randao_commitment_registrations"));
    }

    @Override
    public SszListSchema<PayloadAttestation, ?> getPayloadAttestationsSchema() {
        return null;
    }

    @Override
    public ExecutionRequestsSchema<?> getParentExecutionRequestsSchema() {
        return null;
    }

    @Override
    public ExecutionRequestsSchema<?> getExecutionRequestsSchema() {
        return null;
    }

    @Override
    public SszListSchema<SszKZGCommitment, ?> getBlobKzgCommitmentsSchema() {
        return null;
    }

    @Override
    public long getBlobKzgCommitmentsGeneralizedIndex() {
        return 0;
    }

    @Override
    public SszListSchema<SignedBlsToExecutionChange, ?> getBlsToExecutionChangesSchema() {
        return null;
    }

    @Override
    public ExecutionPayloadSchema<?> getExecutionPayloadSchema() {
        return null;
    }

    @Override
    public SyncAggregateSchema getSyncAggregateSchema() {
        return null;
    }
}