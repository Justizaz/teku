/*
 * Copyright (c) 2026 Consensys Incorporated. All rights reserved.
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

package tech.pegasys.teku.validator.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.units.bigints.UInt256;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import tech.pegasys.teku.bls.BLS;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSSignature;
import tech.pegasys.teku.bls.BLSSignatureVerifier;
import tech.pegasys.teku.infrastructure.async.SafeFuture;
import tech.pegasys.teku.infrastructure.async.StubAsyncRunner;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.Spec;
import tech.pegasys.teku.spec.TestSpecFactory;
import tech.pegasys.teku.spec.cache.IndexedAttestationCache;
import tech.pegasys.teku.spec.config.SpecConfigGloas;
import tech.pegasys.teku.spec.datastructures.blocks.BeaconBlock;
import tech.pegasys.teku.spec.datastructures.blocks.SignedBeaconBlock;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.BeaconBlockBody;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.versions.eip8321.BeaconBlockBodySchemaEip8321;
import tech.pegasys.teku.spec.datastructures.interop.GenesisStateBuilder;
import tech.pegasys.teku.spec.datastructures.interop.MockStartValidatorKeyPairFactory;
import tech.pegasys.teku.spec.datastructures.metadata.BlockContainerAndMetaData;
import tech.pegasys.teku.spec.datastructures.operations.SignedRandaoCommitmentRegistration;
import tech.pegasys.teku.spec.datastructures.state.ForkInfo;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.BeaconStateEip8321;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.gloas.BeaconStateGloas;
import tech.pegasys.teku.spec.logic.common.util.HashChainRandaoUtil;
import tech.pegasys.teku.spec.schemas.SchemaDefinitionsGloas;
import tech.pegasys.teku.spec.signatures.LocalSigner;
import tech.pegasys.teku.spec.signatures.Signer;
import tech.pegasys.teku.spec.signatures.SigningRootUtil;
import tech.pegasys.teku.spec.util.DataStructureUtil;
import tech.pegasys.teku.validator.api.SendSignedBlockResult;
import tech.pegasys.teku.validator.api.ValidatorApiChannel;
import tech.pegasys.teku.validator.beaconnode.GenesisDataProvider;
import tech.pegasys.teku.validator.client.duties.BlockProductionDuty;
import tech.pegasys.teku.validator.client.duties.DutyResult;
import tech.pegasys.teku.validator.client.duties.ValidatorDutyMetrics;
import tech.pegasys.teku.validator.client.duties.execution.ExecutionPayloadBidEventsChannel;
import tech.pegasys.teku.validator.client.hashchain.HashChain;
import tech.pegasys.teku.validator.client.hashchain.HashChainGenerator;
import tech.pegasys.teku.validator.client.hashchain.HashChainStore;
import tech.pegasys.teku.validator.client.hashchain.RandaoCommitmentRegistrator;
import tech.pegasys.teku.validator.client.signer.BlockContainerSigner;

public class Eip8321EndToEndIntegrationTest {

  private Spec spec;
  private DataStructureUtil dataStructureUtil;
  private StubAsyncRunner asyncRunner;
  private ValidatorApiChannel validatorApiChannel;
  private ValidatorIndexProvider validatorIndexProvider;
  private GenesisDataProvider genesisDataProvider;
  private ForkProvider forkProvider;
  private BlockContainerSigner blockContainerSigner;
  private ValidatorDutyMetrics validatorDutyMetrics;
  private ExecutionPayloadBidEventsChannel executionPayloadBidEventsChannel;

  @BeforeEach
  void setUp() {
    spec = TestSpecFactory.createMinimalEip8321();
    dataStructureUtil = new DataStructureUtil(spec);
    asyncRunner = new StubAsyncRunner();
    validatorApiChannel = mock(ValidatorApiChannel.class);
    validatorIndexProvider = mock(ValidatorIndexProvider.class);
    genesisDataProvider = mock(GenesisDataProvider.class);
    forkProvider = mock(ForkProvider.class);
    blockContainerSigner = mock(BlockContainerSigner.class);
    validatorDutyMetrics = mock(ValidatorDutyMetrics.class);
    executionPayloadBidEventsChannel = mock(ExecutionPayloadBidEventsChannel.class);
  }

  @Test
  void shouldExecuteCompleteEip8321ValidatorWorkflow(@TempDir final Path tempDir) throws Exception {
    final int validatorCount = 64;
    final int targetValidatorIndex = 0;
    final int unregisteredValidatorIndex = 1;

    final List<BLSKeyPair> validatorKeyPairs =
        new MockStartValidatorKeyPairFactory().generateKeyPairs(0, validatorCount);
    final BLSKeyPair targetValidatorKeyPair = validatorKeyPairs.get(targetValidatorIndex);
    final BLSKeyPair unregisteredValidatorKeyPair =
        validatorKeyPairs.get(unregisteredValidatorIndex);

    final Signer targetSigner = new LocalSigner(spec, targetValidatorKeyPair, asyncRunner);
    final Signer unregisteredSigner =
        new LocalSigner(spec, unregisteredValidatorKeyPair, asyncRunner);

    final Validator targetValidator =
        new Validator(targetValidatorKeyPair.getPublicKey(), targetSigner, Optional::empty);
    final Validator unregisteredValidator =
        new Validator(
            unregisteredValidatorKeyPair.getPublicKey(), unregisteredSigner, Optional::empty);

    final BeaconState genesisState =
        new GenesisStateBuilder().spec(spec).addValidators(validatorKeyPairs).build();
    final ForkInfo forkInfo = genesisState.getForkInfo();
    when(forkProvider.getForkInfo(any())).thenReturn(SafeFuture.completedFuture(forkInfo));

    // 1. Generate and store a hash chain
    final HashChain hashChain = new HashChainGenerator().generate(65536);
    final Bytes32 commitment = hashChain.getCommitment();
    final HashChainStore hashChainStore = new HashChainStore(tempDir);
    hashChainStore.storeHashChain(targetValidatorKeyPair.getPublicKey(), hashChain, "password");

    assertThat(hashChainStore.hasHashChain(targetValidatorKeyPair.getPublicKey())).isTrue();
    final HashChain loadedChain =
        hashChainStore
            .loadHashChain(targetValidatorKeyPair.getPublicKey(), "password")
            .orElseThrow();
    assertThat(loadedChain.getCommitment()).isEqualTo(commitment);

    // 2. Sign and submit commitment registration through Beacon API
    when(validatorApiChannel.sendSignedRandaoCommitmentRegistration(any()))
        .thenReturn(SafeFuture.COMPLETE);
    when(genesisDataProvider.getGenesisValidatorsRoot())
        .thenReturn(SafeFuture.completedFuture(forkInfo.getGenesisValidatorsRoot()));
    when(validatorIndexProvider.getValidatorIndicesByPublicKey())
        .thenReturn(
            SafeFuture.completedFuture(
                Map.of(targetValidatorKeyPair.getPublicKey(), targetValidatorIndex)));

    final RandaoCommitmentRegistrator registrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel, validatorIndexProvider, genesisDataProvider);

    final SafeFuture<Boolean> registrationFuture =
        registrator.registerValidator(targetValidator, hashChain);
    asyncRunner.executeQueuedActions();
    assertThat(registrationFuture).isCompleted();
    assertThat(registrationFuture.join()).isTrue();

    final ArgumentCaptor<SignedRandaoCommitmentRegistration> captor =
        ArgumentCaptor.forClass(SignedRandaoCommitmentRegistration.class);
    verify(validatorApiChannel).sendSignedRandaoCommitmentRegistration(captor.capture());

    final SignedRandaoCommitmentRegistration submittedRegistration = captor.getValue();
    assertThat(submittedRegistration.getMessage().getValidatorIndex())
        .isEqualTo(UInt64.valueOf(targetValidatorIndex));
    assertThat(submittedRegistration.getMessage().getCommitment()).isEqualTo(commitment);

    // Verify registration signature against genesis validators root
    final SigningRootUtil signingRootUtil = new SigningRootUtil(spec);
    final Bytes expectedSigningRoot =
        signingRootUtil.signingRootForRandaoCommitmentRegistration(
            submittedRegistration.getMessage(), forkInfo.getGenesisValidatorsRoot());
    assertThat(
            BLS.verify(
                targetValidatorKeyPair.getPublicKey(),
                expectedSigningRoot,
                submittedRegistration.getSignature()))
        .isTrue();

    // 3. Include registration in a block and process block
    final UInt64 slot1 = UInt64.ONE;
    final BeaconState slot1State = spec.processSlots(genesisState, slot1);
    final int slot1ProposerIndex = spec.getBeaconProposerIndex(slot1State, slot1);
    final BLSKeyPair slot1ProposerKeyPair = validatorKeyPairs.get(slot1ProposerIndex);

    final BeaconBlock blockWithRegistration =
        createBlock(
            slot1,
            UInt64.valueOf(slot1ProposerIndex),
            slot1State,
            BLS.sign(
                slot1ProposerKeyPair.getSecretKey(),
                signingRootUtil.signingRootForRandaoReveal(
                    spec.computeEpochAtSlot(slot1), forkInfo)),
            Bytes32.ZERO,
            submittedRegistration);

    final BeaconState postBlockState =
        spec.getBlockProcessor(slot1)
            .processUnsignedBlock(
                slot1State,
                blockWithRegistration,
                IndexedAttestationCache.NOOP,
                BLSSignatureVerifier.SIMPLE,
                Optional.empty(),
                Optional.empty());

    final BeaconStateEip8321 eip8321StateAfterBlock = BeaconStateEip8321.required(postBlockState);
    assertThat(eip8321StateAfterBlock.getPendingRandaoCommitments()).hasSize(1);
    assertThat(eip8321StateAfterBlock.getPendingRandaoCommitments().get(0).getValidatorIndex())
        .isEqualTo(UInt64.valueOf(targetValidatorIndex));
    assertThat(eip8321StateAfterBlock.getPendingRandaoCommitments().get(0).getCommitment())
        .isEqualTo(commitment);
    assertThat(eip8321StateAfterBlock.getPendingRandaoCommitments().get(0).getActivationEpoch())
        .isEqualTo(UInt64.valueOf(3));

    // 4. Advance the chain until commitment activates at activation epoch = 3
    final UInt64 activationSlot =
        UInt64.valueOf(spec.getGenesisSpecConfig().getSlotsPerEpoch() * 3L);
    final BeaconState stateAtActivation = spec.processSlots(postBlockState, activationSlot);
    final BeaconStateEip8321 eip8321StateAtActivation =
        BeaconStateEip8321.required(stateAtActivation);

    assertThat(eip8321StateAtActivation.getPendingRandaoCommitments()).isEmpty();
    assertThat(eip8321StateAtActivation.getRandaoCommitments().get(targetValidatorIndex).get())
        .isEqualTo(commitment);

    // 5. Propose a block using BlockProductionDuty with hash-chain reveal when targetValidator is
    // elected
    UInt64 proposalSlot = activationSlot;
    BeaconState stateAtProposalSlot = spec.processSlots(postBlockState, proposalSlot);
    while (spec.getBeaconProposerIndex(stateAtProposalSlot, proposalSlot) != targetValidatorIndex) {
      proposalSlot = proposalSlot.plus(1);
      stateAtProposalSlot = spec.processSlots(postBlockState, proposalSlot);
    }

    when(validatorApiChannel.getValidatorRandaoCommitment(targetValidatorKeyPair.getPublicKey()))
        .thenReturn(SafeFuture.completedFuture(Optional.of(commitment)));

    final Bytes32 expectedPreimage = loadedChain.getRevealForCommitment(commitment).orElseThrow();
    final Bytes32 preProposalMix =
        spec.atSlot(proposalSlot)
            .beaconStateAccessors()
            .getRandaoMix(stateAtProposalSlot, spec.computeEpochAtSlot(proposalSlot));

    final BlockProductionDuty registeredProposerDuty =
        new BlockProductionDuty(
            targetValidator,
            proposalSlot,
            forkProvider,
            validatorApiChannel,
            blockContainerSigner,
            spec,
            validatorDutyMetrics,
            executionPayloadBidEventsChannel,
            BuilderConfigProvider.NOOP,
            Optional.of(hashChainStore),
            Optional.of(loadedChain));

    final BeaconBlock hashChainBlock =
        createBlock(
            proposalSlot,
            UInt64.valueOf(targetValidatorIndex),
            stateAtProposalSlot,
            BLSSignature.infinity(),
            expectedPreimage);

    final BlockContainerAndMetaData blockAndMetadata =
        new BlockContainerAndMetaData(
            hashChainBlock,
            spec.atSlot(proposalSlot).getMilestone(),
            UInt256.ZERO,
            UInt256.ZERO,
            false,
            Optional.empty());

    when(validatorApiChannel.createUnsignedBlock(
            eq(proposalSlot),
            eq(BLSSignature.infinity()),
            eq(Optional.of(expectedPreimage)),
            any(),
            eq(false),
            any()))
        .thenReturn(SafeFuture.completedFuture(Optional.of(blockAndMetadata)));

    final SignedBeaconBlock signedHashChainBlock = dataStructureUtil.signedBlock(hashChainBlock);

    when(blockContainerSigner.sign(hashChainBlock, targetValidator, forkInfo))
        .thenReturn(SafeFuture.completedFuture(signedHashChainBlock));
    when(validatorApiChannel.sendSignedBlock(eq(signedHashChainBlock), any(), any()))
        .thenReturn(
            SafeFuture.completedFuture(
                SendSignedBlockResult.success(signedHashChainBlock.getRoot())));

    final SafeFuture<DutyResult> dutyExecutionFuture = registeredProposerDuty.performDuty();
    asyncRunner.executeQueuedActions();
    assertThat(dutyExecutionFuture).isCompleted();

    // 6. Verify block is processed into state, commitment advances to preimage, and mix updates via
    // BLAKE3
    final BeaconState postHashChainState =
        spec.getBlockProcessor(proposalSlot)
            .processUnsignedBlock(
                stateAtProposalSlot,
                hashChainBlock,
                IndexedAttestationCache.NOOP,
                BLSSignatureVerifier.SIMPLE,
                Optional.empty(),
                Optional.empty());

    final BeaconStateEip8321 eip8321StateAfterReveal =
        BeaconStateEip8321.required(postHashChainState);
    assertThat(eip8321StateAfterReveal.getRandaoCommitments().get(targetValidatorIndex).get())
        .isEqualTo(expectedPreimage);

    final Bytes32 expectedNextMix =
        HashChainRandaoUtil.computeNextMix(preProposalMix, expectedPreimage);
    final Bytes32 actualMix =
        spec.atSlot(proposalSlot)
            .beaconStateAccessors()
            .getRandaoMix(postHashChainState, spec.computeEpochAtSlot(proposalSlot));
    assertThat(actualMix).isEqualTo(expectedNextMix);

    // 7. Verify unregistered validator still uses legacy BLS RANDAO when elected
    UInt64 unregisteredProposalSlot = proposalSlot.plus(1);
    BeaconState stateAtUnregisteredSlot =
        spec.processSlots(postHashChainState, unregisteredProposalSlot);
    while (spec.getBeaconProposerIndex(stateAtUnregisteredSlot, unregisteredProposalSlot)
        != unregisteredValidatorIndex) {
      unregisteredProposalSlot = unregisteredProposalSlot.plus(1);
      stateAtUnregisteredSlot = spec.processSlots(postHashChainState, unregisteredProposalSlot);
    }

    when(validatorApiChannel.getValidatorRandaoCommitment(
            unregisteredValidatorKeyPair.getPublicKey()))
        .thenReturn(SafeFuture.completedFuture(Optional.of(Bytes32.ZERO)));

    final BLSSignature legacyRandaoSignature =
        BLS.sign(
            unregisteredValidatorKeyPair.getSecretKey(),
            signingRootUtil.signingRootForRandaoReveal(
                spec.computeEpochAtSlot(unregisteredProposalSlot),
                stateAtUnregisteredSlot.getForkInfo()));

    final BlockProductionDuty unregisteredProposerDuty =
        new BlockProductionDuty(
            unregisteredValidator,
            unregisteredProposalSlot,
            forkProvider,
            validatorApiChannel,
            blockContainerSigner,
            spec,
            validatorDutyMetrics,
            executionPayloadBidEventsChannel,
            BuilderConfigProvider.NOOP,
            Optional.of(hashChainStore),
            Optional.empty());

    final BeaconBlock legacyBlock =
        createBlock(
            unregisteredProposalSlot,
            UInt64.valueOf(unregisteredValidatorIndex),
            stateAtUnregisteredSlot,
            legacyRandaoSignature,
            Bytes32.ZERO);

    final BlockContainerAndMetaData legacyBlockAndMetadata =
        new BlockContainerAndMetaData(
            legacyBlock,
            spec.atSlot(unregisteredProposalSlot).getMilestone(),
            UInt256.ZERO,
            UInt256.ZERO,
            false,
            Optional.empty());

    when(validatorApiChannel.createUnsignedBlock(
            eq(unregisteredProposalSlot),
            eq(legacyRandaoSignature),
            eq(Optional.empty()),
            any(),
            eq(false),
            any()))
        .thenReturn(SafeFuture.completedFuture(Optional.of(legacyBlockAndMetadata)));

    final SignedBeaconBlock signedLegacyBlock = dataStructureUtil.signedBlock(legacyBlock);

    when(blockContainerSigner.sign(legacyBlock, unregisteredValidator, forkInfo))
        .thenReturn(SafeFuture.completedFuture(signedLegacyBlock));
    when(validatorApiChannel.sendSignedBlock(eq(signedLegacyBlock), any(), any()))
        .thenReturn(
            SafeFuture.completedFuture(SendSignedBlockResult.success(signedLegacyBlock.getRoot())));

    final SafeFuture<DutyResult> unregisteredDutyFuture = unregisteredProposerDuty.performDuty();
    asyncRunner.executeQueuedActions();
    assertThat(unregisteredDutyFuture).isCompleted();

    final BeaconState postLegacyState =
        spec.getBlockProcessor(unregisteredProposalSlot)
            .processUnsignedBlock(
                stateAtUnregisteredSlot,
                legacyBlock,
                IndexedAttestationCache.NOOP,
                BLSSignatureVerifier.SIMPLE,
                Optional.empty(),
                Optional.empty());

    final BeaconStateEip8321 eip8321StateAfterLegacy = BeaconStateEip8321.required(postLegacyState);
    assertThat(eip8321StateAfterLegacy.getRandaoCommitments().get(unregisteredValidatorIndex).get())
        .isEqualTo(Bytes32.ZERO);
    assertThat(eip8321StateAfterLegacy.getRandaoCommitments().get(targetValidatorIndex).get())
        .isEqualTo(expectedPreimage);
  }

  private BeaconBlock createBlock(
      final UInt64 slot,
      final UInt64 proposerIndex,
      final BeaconState preState,
      final BLSSignature randaoReveal,
      final Bytes32 hashChainReveal,
      final SignedRandaoCommitmentRegistration... registrations) {
    final BeaconBlockBody body =
        createBlockBody(slot, preState, randaoReveal, hashChainReveal, registrations);
    return new BeaconBlock(
        spec.getGenesisSchemaDefinitions().getBeaconBlockSchema(),
        slot,
        proposerIndex,
        preState.getLatestBlockHeader().getRoot(),
        dataStructureUtil.randomBytes32(),
        body);
  }

  private BeaconBlockBody createBlockBody(
      final UInt64 slot,
      final BeaconState preState,
      final BLSSignature randaoReveal,
      final Bytes32 hashChainReveal,
      final SignedRandaoCommitmentRegistration... registrations) {
    final BeaconBlockBodySchemaEip8321<?> schema =
        BeaconBlockBodySchemaEip8321.required(
            spec.getGenesisSchemaDefinitions().getBeaconBlockBodySchema());
    final SchemaDefinitionsGloas schemaGloas =
        spec.atSlot(slot).getSchemaDefinitions().toVersionGloas().orElseThrow();
    final BeaconStateGloas stateGloas = BeaconStateGloas.required(preState);
    final Bytes32 parentBlockHash = stateGloas.getLatestBlockHash();
    final Bytes32 parentBlockRoot =
        spec.atSlot(slot).beaconStateAccessors().getBlockRootAtSlot(preState, slot.minusMinZero(1));
    final Bytes32 prevRandao =
        spec.atSlot(slot)
            .beaconStateAccessors()
            .getRandaoMix(preState, spec.computeEpochAtSlot(slot));
    return schema
        .createBlockBody(
            builder -> {
              builder
                  .randaoReveal(randaoReveal)
                  .eth1Data(dataStructureUtil.randomEth1Data())
                  .graffiti(Bytes32.ZERO)
                  .attestations(schema.getAttestationsSchema().of())
                  .proposerSlashings(schema.getProposerSlashingsSchema().of())
                  .attesterSlashings(schema.getAttesterSlashingsSchema().of())
                  .deposits(schema.getDepositsSchema().of())
                  .voluntaryExits(schema.getVoluntaryExitsSchema().of())
                  .syncAggregate(dataStructureUtil.emptySyncAggregateIfRequiredByState(preState))
                  .blsToExecutionChanges(schema.getBlsToExecutionChangesSchema().of())
                  .signedExecutionPayloadBid(
                      schemaGloas
                          .getSignedExecutionPayloadBidSchema()
                          .create(
                              schemaGloas
                                  .getExecutionPayloadBidSchema()
                                  .create(
                                      parentBlockHash,
                                      parentBlockRoot,
                                      dataStructureUtil.randomBytes32(),
                                      prevRandao,
                                      dataStructureUtil.randomEth1Address(),
                                      dataStructureUtil.randomUInt64(),
                                      SpecConfigGloas.BUILDER_INDEX_SELF_BUILD,
                                      slot,
                                      UInt64.ZERO,
                                      UInt64.ZERO,
                                      schemaGloas
                                          .getExecutionPayloadBidSchema()
                                          .getBlobKzgCommitmentsSchema()
                                          .createFromElements(List.of()),
                                      dataStructureUtil.randomBytes32()),
                              BLSSignature.infinity()))
                  .payloadAttestations(schema.getPayloadAttestationsSchema().of())
                  .parentExecutionRequests(dataStructureUtil.emptyExecutionRequests(slot));
              builder.hashChainReveal(hashChainReveal);
              if (registrations.length > 0) {
                builder.randaoCommitmentRegistrations(
                    schema.getRandaoCommitmentRegistrationsSchema().of(registrations));
              } else {
                builder.randaoCommitmentRegistrations(
                    schema.getRandaoCommitmentRegistrationsSchema().of());
              }
              return SafeFuture.COMPLETE;
            })
        .join();
  }
}
