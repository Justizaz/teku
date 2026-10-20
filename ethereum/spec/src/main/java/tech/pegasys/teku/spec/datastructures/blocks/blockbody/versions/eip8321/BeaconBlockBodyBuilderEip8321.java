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

import org.apache.tuweni.bytes.Bytes32;
import tech.pegasys.teku.infrastructure.ssz.SszList;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszBytes32;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.BeaconBlockBody;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.BeaconBlockBodyBuilder;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.BeaconBlockBodySchema;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.versions.gloas.BeaconBlockBodyBuilderGloas;
import tech.pegasys.teku.spec.datastructures.epbs.versions.gloas.PayloadAttestation;
import tech.pegasys.teku.spec.datastructures.epbs.versions.gloas.SignedExecutionPayloadBid;
import tech.pegasys.teku.spec.datastructures.execution.ExecutionRequests;
import tech.pegasys.teku.spec.datastructures.operations.SignedRandaoCommitmentRegistration;
import tech.pegasys.teku.spec.datastructures.type.SszSignature;

import static com.google.common.base.Preconditions.checkNotNull;

public class BeaconBlockBodyBuilderEip8321 extends BeaconBlockBodyBuilderGloas {

  private SignedExecutionPayloadBid signedExecutionPayloadBid;
  private SszList<PayloadAttestation> payloadAttestations;
  private ExecutionRequests parentExecutionRequests;
  private Bytes32 hashChainReveal = Bytes32.ZERO;
  private SszList<SignedRandaoCommitmentRegistration> randaoCommitmentRegistrations;

  public BeaconBlockBodyBuilderEip8321(
      final BeaconBlockBodySchema<? extends BeaconBlockBodyEip8321> schema) {
    super(schema);

    this.randaoCommitmentRegistrations =
            ((BeaconBlockBodySchemaEip8321<?>) schema)
                    .getRandaoCommitmentRegistrationsSchema()
                    .of();
  }

  @Override
  public Boolean supportsExecutionPayload() {
    return false;
  }

  @Override
  public Boolean supportsKzgCommitments() {
    return false;
  }

  @Override
  public boolean supportsExecutionRequests() {
    return false;
  }

  @Override
  public Boolean supportsSignedExecutionPayloadBid() {
    return true;
  }

  @Override
  public BeaconBlockBodyBuilder signedExecutionPayloadBid(
      final SignedExecutionPayloadBid signedExecutionPayloadBid) {
    this.signedExecutionPayloadBid = signedExecutionPayloadBid;
    return this;
  }

  @Override
  public Boolean supportsPayloadAttestations() {
    return true;
  }

  @Override
  public BeaconBlockBodyBuilder payloadAttestations(
      final SszList<PayloadAttestation> payloadAttestations) {
    this.payloadAttestations = payloadAttestations;
    return this;
  }

  @Override
  public Boolean supportsParentExecutionRequests() {
    return true;
  }

  @Override
  public BeaconBlockBodyBuilder parentExecutionRequests(
      final ExecutionRequests parentExecutionRequests) {
    this.parentExecutionRequests = parentExecutionRequests;
    return this;
  }

  public BeaconBlockBodyBuilderEip8321 hashChainReveal(final Bytes32 hashChainReveal) {
    this.hashChainReveal = hashChainReveal;
    return this;
  }

  public BeaconBlockBodyBuilderEip8321 randaoCommitmentRegistrations(final SszList<SignedRandaoCommitmentRegistration> randaoCommitmentRegistrations) {
    this.randaoCommitmentRegistrations = randaoCommitmentRegistrations;
    return this;
  }

  @Override
  protected void validate() {
    // skipping super.validate() because fields were removed
    // old fields
    checkNotNull(randaoReveal, "randaoReveal must be specified");
    checkNotNull(eth1Data, "eth1Data must be specified");
    checkNotNull(graffiti, "graffiti must be specified");
    checkNotNull(attestations, "attestations must be specified");
    checkNotNull(proposerSlashings, "proposerSlashings must be specified");
    checkNotNull(attesterSlashings, "attesterSlashings must be specified");
    checkNotNull(deposits, "deposits must be specified");
    checkNotNull(voluntaryExits, "voluntaryExits must be specified");
    checkNotNull(syncAggregate, "syncAggregate must be specified");
    checkNotNull(blsToExecutionChanges, "blsToExecutionChanges must be specified");
    // new fields
    checkNotNull(signedExecutionPayloadBid, "signedExecutionPayloadBid must be specified");
    checkNotNull(payloadAttestations, "payloadAttestations must be specified");
    checkNotNull(parentExecutionRequests, "parentExecutionRequests must be specified");
    checkNotNull(randaoCommitmentRegistrations, "randaoCommitmentRegistrations must be specified");
  }

  @Override
  protected Boolean isBlinded() {
    return false;
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
        getBlsToExecutionChanges(),
        signedExecutionPayloadBid,
        payloadAttestations,
        parentExecutionRequests,
            SszBytes32.of(hashChainReveal),
            randaoCommitmentRegistrations);
  }
}
