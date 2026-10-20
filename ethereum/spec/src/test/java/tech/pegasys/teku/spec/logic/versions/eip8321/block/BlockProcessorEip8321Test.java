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

package tech.pegasys.teku.spec.logic.versions.eip8321.block;

import static org.assertj.core.api.Assertions.assertThat;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;
import tech.pegasys.teku.bls.BLS;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSSignature;
import tech.pegasys.teku.bls.BLSSignatureVerifier;
import tech.pegasys.teku.bls.BLSTestUtil;
import tech.pegasys.teku.infrastructure.async.SafeFuture;
import tech.pegasys.teku.infrastructure.crypto.Hash;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszBytes32;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.Spec;
import tech.pegasys.teku.spec.TestSpecFactory;
import tech.pegasys.teku.spec.constants.Domain;
import tech.pegasys.teku.spec.datastructures.blocks.BeaconBlock;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.BeaconBlockBody;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.versions.eip8321.BeaconBlockBodyBuilderEip8321;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.versions.eip8321.BeaconBlockBodyEip8321;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.versions.eip8321.BeaconBlockBodySchemaEip8321;
import tech.pegasys.teku.spec.datastructures.operations.RandaoCommitmentRegistration;
import tech.pegasys.teku.spec.datastructures.operations.SignedRandaoCommitmentRegistration;
import tech.pegasys.teku.spec.datastructures.state.Validator;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.BeaconStateEip8321;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.MutableBeaconStateEip8321;
import tech.pegasys.teku.spec.logic.common.statetransition.blockvalidator.BlockValidationResult;
import tech.pegasys.teku.spec.logic.common.util.HashChainRandaoUtil;
import tech.pegasys.teku.spec.util.DataStructureUtil;

class BlockProcessorEip8321Test {

    private final Spec spec = TestSpecFactory.createMinimalEip8321();
    private final DataStructureUtil dataStructureUtil = new DataStructureUtil(spec);
    private final BlockProcessorEip8321 blockProcessor =
            (BlockProcessorEip8321) spec.getGenesisSpec().getBlockProcessor();

    private final BLSKeyPair proposerKeyPair = BLSTestUtil.randomKeyPair(42);

    @Test
    void verifyRandao_hashChain_validReveal_shouldSucceed() {
        final Bytes32 reveal = dataStructureUtil.randomBytes32();
        final Bytes32 commitment = HashChainRandaoUtil.computeCommitment(reveal);

        final BeaconStateEip8321 state = createStateWithProposer(proposerKeyPair, commitment);
        final int proposerIndex = spec.getBeaconProposerIndex(state, UInt64.ZERO);
        final BeaconBlock block =
                createBlock(UInt64.ZERO, UInt64.valueOf(proposerIndex), BLSSignature.infinity(), reveal);

        final BlockValidationResult result =
                blockProcessor.verifyRandao(state, block, BLSSignatureVerifier.SIMPLE);

        assertThat(result.isValid()).isTrue();
    }

    @Test
    void verifyRandao_hashChain_zeroReveal_shouldFail() {
        final Bytes32 reveal = dataStructureUtil.randomBytes32();
        final Bytes32 commitment = HashChainRandaoUtil.computeCommitment(reveal);

        final BeaconStateEip8321 state = createStateWithProposer(proposerKeyPair, commitment);
        final int proposerIndex = spec.getBeaconProposerIndex(state, UInt64.ZERO);
        final BeaconBlock block =
                createBlock(
                        UInt64.ZERO, UInt64.valueOf(proposerIndex), BLSSignature.infinity(), Bytes32.ZERO);

        final BlockValidationResult result =
                blockProcessor.verifyRandao(state, block, BLSSignatureVerifier.SIMPLE);

        assertThat(result.isValid()).isFalse();
        assertThat(result.getFailureReason()).contains("Hash chain reveal is zero.");
    }

    @Test
    void verifyRandao_hashChain_invalidPreimage_shouldFail() {
        final Bytes32 actualPreimage = dataStructureUtil.randomBytes32();
        final Bytes32 badPreimage = dataStructureUtil.randomBytes32();
        final Bytes32 commitment = HashChainRandaoUtil.computeCommitment(actualPreimage);

        final BeaconStateEip8321 state = createStateWithProposer(proposerKeyPair, commitment);
        final int proposerIndex = spec.getBeaconProposerIndex(state, UInt64.ZERO);
        final BeaconBlock block =
                createBlock(
                        UInt64.ZERO, UInt64.valueOf(proposerIndex), BLSSignature.infinity(), badPreimage);

        final BlockValidationResult result =
                blockProcessor.verifyRandao(state, block, BLSSignatureVerifier.SIMPLE);

        assertThat(result.isValid()).isFalse();
        assertThat(result.getFailureReason()).contains("Hash chain reveal is invalid.");
    }

    @Test
    void verifyRandao_hashChain_nonInfinityBLSSignature_shouldFail() {
        final Bytes32 reveal = dataStructureUtil.randomBytes32();
        final Bytes32 commitment = HashChainRandaoUtil.computeCommitment(reveal);
        final BLSSignature randomSignature = dataStructureUtil.randomSignature();

        final BeaconStateEip8321 state = createStateWithProposer(proposerKeyPair, commitment);
        final int proposerIndex = spec.getBeaconProposerIndex(state, UInt64.ZERO);
        final BeaconBlock block =
                createBlock(UInt64.ZERO, UInt64.valueOf(proposerIndex), randomSignature, reveal);

        final BlockValidationResult result =
                blockProcessor.verifyRandao(state, block, BLSSignatureVerifier.SIMPLE);

        assertThat(result.isValid()).isFalse();
        assertThat(result.getFailureReason())
                .contains("Expected BLS signature at infinity for hash chain reveal.");
    }

    @Test
    void verifyRandao_legacy_validBLSSignature_shouldSucceed() {
        final BeaconStateEip8321 state = createStateWithProposer(proposerKeyPair, Bytes32.ZERO);
        final int proposerIndex = spec.getBeaconProposerIndex(state, UInt64.ZERO);
        final UInt64 epoch = spec.computeEpochAtSlot(UInt64.ZERO);
        final Bytes32 domain =
                spec.getDomain(Domain.RANDAO, epoch, state.getFork(), state.getGenesisValidatorsRoot());
        final Bytes signingRoot = spec.computeSigningRoot(epoch, domain);
        final BLSSignature validSignature = BLS.sign(proposerKeyPair.getSecretKey(), signingRoot);

        final BeaconBlock block =
                createBlock(
                        UInt64.ZERO, UInt64.valueOf(proposerIndex), validSignature, Bytes32.ZERO);

        final BlockValidationResult result =
                blockProcessor.verifyRandao(state, block, BLSSignatureVerifier.SIMPLE);

        assertThat(result.isValid()).isTrue();
    }

    @Test
    void verifyRandao_legacy_nonZeroHashChainReveal_shouldFail() {
        final BeaconStateEip8321 state = createStateWithProposer(proposerKeyPair, Bytes32.ZERO);
        final int proposerIndex = spec.getBeaconProposerIndex(state, UInt64.ZERO);
        final UInt64 epoch = spec.computeEpochAtSlot(UInt64.ZERO);
        final Bytes32 domain =
                spec.getDomain(Domain.RANDAO, epoch, state.getFork(), state.getGenesisValidatorsRoot());
        final Bytes signingRoot = spec.computeSigningRoot(epoch, domain);
        final BLSSignature validSignature = BLS.sign(proposerKeyPair.getSecretKey(), signingRoot);
        final Bytes32 nonZeroReveal = dataStructureUtil.randomBytes32();

        final BeaconBlock block =
                createBlock(
                        UInt64.ZERO, UInt64.valueOf(proposerIndex), validSignature, nonZeroReveal);

        final BlockValidationResult result =
                blockProcessor.verifyRandao(state, block, BLSSignatureVerifier.SIMPLE);

        assertThat(result.isValid()).isFalse();
        assertThat(result.getFailureReason())
                .contains("Expected zero hash chain reveal for legacy RANDAO.");
    }

    @Test
    void verifyRandao_legacy_invalidBLSSignature_shouldFail() {
        final BeaconStateEip8321 state = createStateWithProposer(proposerKeyPair, Bytes32.ZERO);
        final int proposerIndex = spec.getBeaconProposerIndex(state, UInt64.ZERO);
        final BLSSignature invalidSignature = dataStructureUtil.randomSignature();

        final BeaconBlock block =
                createBlock(
                        UInt64.ZERO, UInt64.valueOf(proposerIndex), invalidSignature, Bytes32.ZERO);

        final BlockValidationResult result =
                blockProcessor.verifyRandao(state, block, BLSSignatureVerifier.SIMPLE);

        assertThat(result.isValid()).isFalse();
        assertThat(result.getFailureReason()).contains("Randao reveal is invalid.");
    }

    @Test
    void verifyRandao_doesNotMutateState() {
        final Bytes32 reveal = dataStructureUtil.randomBytes32();
        final Bytes32 commitment = HashChainRandaoUtil.computeCommitment(reveal);

        final BeaconStateEip8321 state = createStateWithProposer(proposerKeyPair, commitment);
        final Bytes32 preHashRoot = state.hashTreeRoot();
        final int proposerIndex = spec.getBeaconProposerIndex(state, UInt64.ZERO);
        final BeaconBlock block =
                createBlock(UInt64.ZERO, UInt64.valueOf(proposerIndex), BLSSignature.infinity(), reveal);

        blockProcessor.verifyRandao(state, block, BLSSignatureVerifier.SIMPLE);

        assertThat(state.hashTreeRoot()).isEqualTo(preHashRoot);
    }

    @Test
    void processRandaoNoValidation_hashChain_updatesMixAndCommitment() throws Exception {
        final Bytes32 reveal = dataStructureUtil.randomBytes32();
        final Bytes32 commitment = HashChainRandaoUtil.computeCommitment(reveal);

        final BeaconStateEip8321 preState = createStateWithProposer(proposerKeyPair, commitment);
        final int proposerIndex = spec.getBeaconProposerIndex(preState, UInt64.ZERO);
        final UInt64 epoch = spec.computeEpochAtSlot(UInt64.ZERO);
        final Bytes32 initialMix = spec.getRandaoMix(preState, epoch);
        final int mixIndex =
                epoch.mod(spec.getGenesisSpecConfig().getEpochsPerHistoricalVector()).intValue();

        final BeaconBlockBody body = createBlockBody(BLSSignature.infinity(), reveal);
        final MutableBeaconStateEip8321 mutableState = preState.createWritableCopy();

        blockProcessor.processRandaoNoValidation(mutableState, body);

        final Bytes32 expectedMix = HashChainRandaoUtil.computeNextMix(initialMix, reveal);
        assertThat(mutableState.getRandaoMixes().get(mixIndex).get()).isEqualTo(expectedMix);
        assertThat(mutableState.getRandaoCommitments().get(proposerIndex).get()).isEqualTo(reveal);
    }

    @Test
    void processRandaoNoValidation_legacy_updatesMixAndLeavesCommitmentUnchanged() throws Exception {
        final BeaconStateEip8321 preState = createStateWithProposer(proposerKeyPair, Bytes32.ZERO);
        final int proposerIndex = spec.getBeaconProposerIndex(preState, UInt64.ZERO);
        final UInt64 epoch = spec.computeEpochAtSlot(UInt64.ZERO);
        final Bytes32 initialMix = spec.getRandaoMix(preState, epoch);
        final int mixIndex =
                epoch.mod(spec.getGenesisSpecConfig().getEpochsPerHistoricalVector()).intValue();

        final BLSSignature signature = dataStructureUtil.randomSignature();
        final BeaconBlockBody body = createBlockBody(signature, Bytes32.ZERO);
        final MutableBeaconStateEip8321 mutableState = preState.createWritableCopy();

        blockProcessor.processRandaoNoValidation(mutableState, body);

        final Bytes32 expectedMix = initialMix.xor(Hash.sha256(signature.toSSZBytes()));
        assertThat(mutableState.getRandaoMixes().get(mixIndex).get()).isEqualTo(expectedMix);
        assertThat(mutableState.getRandaoCommitments().get(proposerIndex).get())
                .isEqualTo(Bytes32.ZERO);
    }

    @Test
    void regression_gloasBehaviorUnchanged() {
        final Spec specGloas = TestSpecFactory.createMinimalGloas();
        final DataStructureUtil gloasUtil = new DataStructureUtil(specGloas);

        final BeaconState baseState =
                gloasUtil.randomBeaconStateWithActiveValidators(16, UInt64.ZERO);
        final int proposerIndex = specGloas.getBeaconProposerIndex(baseState, UInt64.ZERO);

        final BeaconState state =
                baseState.updated(
                        mutableState -> {
                            final Validator currentProposer = mutableState.getValidators().get(proposerIndex);
                            final Validator updatedProposer =
                                    new Validator(
                                            proposerKeyPair.getPublicKey(),
                                            currentProposer.getWithdrawalCredentials(),
                                            currentProposer.getEffectiveBalance(),
                                            currentProposer.isSlashed(),
                                            currentProposer.getActivationEligibilityEpoch(),
                                            currentProposer.getActivationEpoch(),
                                            currentProposer.getExitEpoch(),
                                            currentProposer.getWithdrawableEpoch());
                            mutableState.getValidators().set(proposerIndex, updatedProposer);
                        });

        final UInt64 epoch = specGloas.computeEpochAtSlot(UInt64.ZERO);
        final Bytes32 domain =
                specGloas.getDomain(Domain.RANDAO, epoch, state.getFork(), state.getGenesisValidatorsRoot());
        final Bytes signingRoot = specGloas.computeSigningRoot(epoch, domain);
        final BLSSignature validSignature = BLS.sign(proposerKeyPair.getSecretKey(), signingRoot);

        final BeaconBlock block =
                new BeaconBlock(
                        specGloas.getGenesisSchemaDefinitions().getBeaconBlockSchema(),
                        UInt64.ZERO,
                        UInt64.valueOf(proposerIndex),
                        gloasUtil.randomBytes32(),
                        gloasUtil.randomBytes32(),
                        gloasUtil.randomBeaconBlockBody(
                                UInt64.ZERO, builder -> builder.randaoReveal(validSignature)));

        final BlockValidationResult result =
                blockProcessor.verifyRandao(state, block, BLSSignatureVerifier.SIMPLE);

        assertThat(result.isValid()).isTrue();
    }

    private BeaconStateEip8321 createStateWithProposer(
            final BLSKeyPair proposerKeyPair, final Bytes32 proposerCommitment) {
        final Spec specGloas = TestSpecFactory.createMinimalGloas();
        final DataStructureUtil gloasUtil = new DataStructureUtil(specGloas);
        final BeaconState baseState =
                gloasUtil.randomBeaconStateWithActiveValidators(16, UInt64.ZERO);
        final int proposerIndex = specGloas.getBeaconProposerIndex(baseState, UInt64.ZERO);

        final BeaconState updatedBaseState =
                baseState.updated(
                        mutableState -> {
                            final Validator currentProposer = mutableState.getValidators().get(proposerIndex);
                            final Validator updatedProposer =
                                    new Validator(
                                            proposerKeyPair.getPublicKey(),
                                            currentProposer.getWithdrawalCredentials(),
                                            currentProposer.getEffectiveBalance(),
                                            currentProposer.isSlashed(),
                                            currentProposer.getActivationEligibilityEpoch(),
                                            currentProposer.getActivationEpoch(),
                                            currentProposer.getExitEpoch(),
                                            currentProposer.getWithdrawableEpoch());
                            mutableState.getValidators().set(proposerIndex, updatedProposer);
                        });

        final BeaconStateEip8321 upgradedState =
                (BeaconStateEip8321)
                        spec.getGenesisSpec().getStateUpgrade().orElseThrow().upgrade(updatedBaseState);

        if (proposerCommitment.isZero()) {
            return upgradedState;
        }

        return upgradedState.updatedEip8321(
                mutableEip8321 -> {
                    mutableEip8321
                            .getRandaoCommitments()
                            .set(proposerIndex, SszBytes32.of(proposerCommitment));
                });
    }

    private BeaconBlock createBlock(
            final UInt64 slot,
            final UInt64 proposerIndex,
            final BLSSignature randaoReveal,
            final Bytes32 hashChainReveal) {
        final BeaconBlockBody body = createBlockBody(randaoReveal, hashChainReveal);
        return new BeaconBlock(
                spec.getGenesisSchemaDefinitions().getBeaconBlockSchema(),
                slot,
                proposerIndex,
                dataStructureUtil.randomBytes32(),
                dataStructureUtil.randomBytes32(),
                body);
    }

    private BeaconBlockBody createBlockBody(
            final BLSSignature randaoReveal, final Bytes32 hashChainReveal) {
        final BeaconBlockBodySchemaEip8321<?> schema =
                (BeaconBlockBodySchemaEip8321<?>)
                        spec.getGenesisSchemaDefinitions().getBeaconBlockBodySchema();
        return (BeaconBlockBodyEip8321)
                schema
                        .createBlockBody(
                                builder -> {
                                    final BeaconBlockBodyBuilderEip8321 eip8321Builder =
                                            (BeaconBlockBodyBuilderEip8321) builder;
                                    eip8321Builder
                                            .randaoReveal(randaoReveal)
                                            .eth1Data(dataStructureUtil.randomEth1Data())
                                            .graffiti(Bytes32.ZERO)
                                            .attestations(
                                                    dataStructureUtil.randomSszList(
                                                            schema.getAttestationsSchema(),
                                                            () -> dataStructureUtil.randomAttestation(UInt64.ZERO),
                                                            1))
                                            .proposerSlashings(
                                                    dataStructureUtil.randomSszList(
                                                            schema.getProposerSlashingsSchema(),
                                                            dataStructureUtil::randomProposerSlashing,
                                                            0))
                                            .attesterSlashings(
                                                    dataStructureUtil.randomSszList(
                                                            schema.getAttesterSlashingsSchema(),
                                                            () -> dataStructureUtil.randomAttesterSlashingAtSlot(UInt64.ZERO),
                                                            0))
                                            .deposits(
                                                    dataStructureUtil.randomSszList(
                                                            schema.getDepositsSchema(),
                                                            dataStructureUtil::randomDepositWithoutIndex,
                                                            0))
                                            .voluntaryExits(
                                                    dataStructureUtil.randomSszList(
                                                            schema.getVoluntaryExitsSchema(),
                                                            dataStructureUtil::randomSignedVoluntaryExit,
                                                            0))
                                            .syncAggregate(dataStructureUtil.randomSyncAggregate())
                                            .blsToExecutionChanges(
                                                    dataStructureUtil.randomSignedBlsToExecutionChangesList())
                                            .signedExecutionPayloadBid(
                                                    dataStructureUtil.randomSignedExecutionPayloadBid())
                                            .payloadAttestations(
                                                    dataStructureUtil.randomSszList(
                                                            schema.getPayloadAttestationsSchema(),
                                                            dataStructureUtil::randomPayloadAttestation,
                                                            1))
                                            .parentExecutionRequests(dataStructureUtil.randomExecutionRequests());
                                    eip8321Builder.hashChainReveal(hashChainReveal);
                                    eip8321Builder.randaoCommitmentRegistrations(
                                            dataStructureUtil.randomSszList(
                                                    schema.getRandaoCommitmentRegistrationsSchema(),
                                                    () ->
                                                            new SignedRandaoCommitmentRegistration(
                                                                    new RandaoCommitmentRegistration(
                                                                            dataStructureUtil.randomValidatorIndex(),
                                                                            dataStructureUtil.randomBytes32()),
                                                                    dataStructureUtil.randomSignature()),
                                                    0));
                                    return SafeFuture.COMPLETE;
                                })
                        .join();
    }
}
