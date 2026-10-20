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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Optional;

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
import tech.pegasys.teku.infrastructure.ssz.SszList;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszBytes32;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.Spec;
import tech.pegasys.teku.spec.TestSpecFactory;
import tech.pegasys.teku.spec.cache.IndexedAttestationCache;
import tech.pegasys.teku.spec.constants.Domain;
import tech.pegasys.teku.spec.datastructures.blocks.BeaconBlock;
import tech.pegasys.teku.spec.datastructures.blocks.SignedBeaconBlock;
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
import tech.pegasys.teku.spec.logic.common.statetransition.exceptions.BlockProcessingException;
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

    @Test
    void verifyRandaoCommitmentRegistrations_validRegistration_shouldSucceed() {
        final BeaconStateEip8321 state = createStateWithProposer(proposerKeyPair, Bytes32.ZERO);
        final BLSKeyPair validatorKeyPair = BLSTestUtil.randomKeyPair(100);
        final BeaconStateEip8321 stateWithValidator = setValidatorPubKey(state, 1, validatorKeyPair);

        final Bytes32 commitment = dataStructureUtil.randomBytes32();
        final SignedRandaoCommitmentRegistration registration =
                createSignedRegistration(stateWithValidator, validatorKeyPair, 1, commitment);

        final SszList<SignedRandaoCommitmentRegistration> registrations =
                createRegistrationsList(registration);

        final BlockValidationResult result =
                blockProcessor.verifyRandaoCommitmentRegistrationsPreProcessing(
                        stateWithValidator, registrations, BLSSignatureVerifier.SIMPLE);

        assertThat(result.isValid()).isTrue();
    }

    @Test
    void verifyRandaoCommitmentRegistrations_duplicateInBlock_shouldFail() {
        final BeaconStateEip8321 state = createStateWithProposer(proposerKeyPair, Bytes32.ZERO);
        final BLSKeyPair validatorKeyPair = BLSTestUtil.randomKeyPair(100);
        final BeaconStateEip8321 stateWithValidator = setValidatorPubKey(state, 1, validatorKeyPair);

        final SignedRandaoCommitmentRegistration reg1 =
                createSignedRegistration(stateWithValidator, validatorKeyPair, 1, dataStructureUtil.randomBytes32());
        final SignedRandaoCommitmentRegistration reg2 =
                createSignedRegistration(stateWithValidator, validatorKeyPair, 1, dataStructureUtil.randomBytes32());

        final SszList<SignedRandaoCommitmentRegistration> registrations =
                createRegistrationsList(reg1, reg2);

        final BlockValidationResult result =
                blockProcessor.verifyRandaoCommitmentRegistrationsPreProcessing(
                        stateWithValidator, registrations, BLSSignatureVerifier.SIMPLE);

        assertThat(result.isValid()).isFalse();
        assertThat(result.getFailureReason()).contains("Duplicated RandaoCommitmentRegistration for validator 1");
    }

    @Test
    void verifyRandaoCommitmentRegistrations_invalidSignature_shouldFail() {
        final BeaconStateEip8321 state = createStateWithProposer(proposerKeyPair, Bytes32.ZERO);
        final BLSKeyPair validatorKeyPair = BLSTestUtil.randomKeyPair(100);
        final BLSKeyPair wrongKeyPair = BLSTestUtil.randomKeyPair(101);
        final BeaconStateEip8321 stateWithValidator = setValidatorPubKey(state, 1, validatorKeyPair);

        // Signed with wrong key
        final SignedRandaoCommitmentRegistration registration =
                createSignedRegistration(stateWithValidator, wrongKeyPair, 1, dataStructureUtil.randomBytes32());

        final SszList<SignedRandaoCommitmentRegistration> registrations =
                createRegistrationsList(registration);

        final BlockValidationResult result =
                blockProcessor.verifyRandaoCommitmentRegistrationsPreProcessing(
                        stateWithValidator, registrations, BLSSignatureVerifier.SIMPLE);

        assertThat(result.isValid()).isFalse();
        assertThat(result.getFailureReason()).contains("RandaoCommitmentRegistration signature is invalid");
    }

    @Test
    void verifyRandaoCommitmentRegistrations_alreadyRegistered_shouldFail() {
        final BeaconStateEip8321 state = createStateWithProposer(proposerKeyPair, Bytes32.ZERO);
        final BLSKeyPair validatorKeyPair = BLSTestUtil.randomKeyPair(100);
        final BeaconStateEip8321 stateWithValidator =
                setValidatorPubKey(state, 1, validatorKeyPair)
                        .updatedEip8321(
                                mutableState ->
                                        mutableState
                                                .getRandaoCommitments()
                                                .set(1, SszBytes32.of(dataStructureUtil.randomBytes32())));

        final SignedRandaoCommitmentRegistration registration =
                createSignedRegistration(stateWithValidator, validatorKeyPair, 1, dataStructureUtil.randomBytes32());

        final SszList<SignedRandaoCommitmentRegistration> registrations =
                createRegistrationsList(registration);

        final BlockValidationResult result =
                blockProcessor.verifyRandaoCommitmentRegistrationsPreProcessing(
                        stateWithValidator, registrations, BLSSignatureVerifier.SIMPLE);

        assertThat(result.isValid()).isFalse();
        assertThat(result.getFailureReason()).contains("already has a registered commitment");
    }

    @Test
    void verifyRandaoCommitmentRegistrations_zeroCommitment_shouldFail() {
        final BeaconStateEip8321 state = createStateWithProposer(proposerKeyPair, Bytes32.ZERO);
        final BLSKeyPair validatorKeyPair = BLSTestUtil.randomKeyPair(100);
        final BeaconStateEip8321 stateWithValidator = setValidatorPubKey(state, 1, validatorKeyPair);

        final SignedRandaoCommitmentRegistration registration =
                createSignedRegistration(stateWithValidator, validatorKeyPair, 1, Bytes32.ZERO);

        final SszList<SignedRandaoCommitmentRegistration> registrations =
                createRegistrationsList(registration);

        final BlockValidationResult result =
                blockProcessor.verifyRandaoCommitmentRegistrationsPreProcessing(
                        stateWithValidator, registrations, BLSSignatureVerifier.SIMPLE);

        assertThat(result.isValid()).isFalse();
        assertThat(result.getFailureReason()).contains("Commitment cannot be zero");
    }

    @Test
    void processRandaoCommitmentRegistrations_shouldAppendPendingCommitment() throws Exception {
        final BeaconStateEip8321 state = createStateWithProposer(proposerKeyPair, Bytes32.ZERO);
        final BLSKeyPair validator1KeyPair = BLSTestUtil.randomKeyPair(101);
        final BLSKeyPair validator2KeyPair = BLSTestUtil.randomKeyPair(102);
        BeaconStateEip8321 stateWithValidators = setValidatorPubKey(state, 1, validator1KeyPair);
        stateWithValidators = setValidatorPubKey(stateWithValidators, 2, validator2KeyPair);

        final Bytes32 commitment1 = dataStructureUtil.randomBytes32();
        final Bytes32 commitment2 = dataStructureUtil.randomBytes32();

        final SignedRandaoCommitmentRegistration reg1 =
                createSignedRegistration(stateWithValidators, validator1KeyPair, 1, commitment1);
        final SignedRandaoCommitmentRegistration reg2 =
                createSignedRegistration(stateWithValidators, validator2KeyPair, 2, commitment2);

        final SszList<SignedRandaoCommitmentRegistration> registrations =
                createRegistrationsList(reg1, reg2);

        final MutableBeaconStateEip8321 mutableState = stateWithValidators.createWritableCopy();
        blockProcessor.processRandaoCommitmentRegistrations(mutableState, registrations);

        final UInt64 expectedActivationEpoch =
                spec.computeEpochAtSlot(mutableState.getSlot())
                        .plus(spec.getGenesisSpecConfig().toVersionEip8321().orElseThrow().getCommitmentRegistrationDelay());

        assertThat(mutableState.getPendingRandaoCommitments()).hasSize(2);
        assertThat(mutableState.getPendingRandaoCommitments().get(0).getValidatorIndex())
                .isEqualTo(UInt64.valueOf(1));
        assertThat(mutableState.getPendingRandaoCommitments().get(0).getCommitment())
                .isEqualTo(commitment1);
        assertThat(mutableState.getPendingRandaoCommitments().get(0).getActivationEpoch())
                .isEqualTo(expectedActivationEpoch);

        assertThat(mutableState.getPendingRandaoCommitments().get(1).getValidatorIndex())
                .isEqualTo(UInt64.valueOf(2));
        assertThat(mutableState.getPendingRandaoCommitments().get(1).getCommitment())
                .isEqualTo(commitment2);
        assertThat(mutableState.getPendingRandaoCommitments().get(1).getActivationEpoch())
                .isEqualTo(expectedActivationEpoch);
    }

    @Test
    void validateBlockPreProcessing_withRegistrations_shouldSucceed() throws Exception {
        final BeaconStateEip8321 state = createStateWithProposer(proposerKeyPair, Bytes32.ZERO);
        final BLSKeyPair validatorKeyPair = BLSTestUtil.randomKeyPair(100);
        final BeaconStateEip8321 stateWithValidator = setValidatorPubKey(state, 1, validatorKeyPair);

        final Bytes32 commitment = dataStructureUtil.randomBytes32();
        final SignedRandaoCommitmentRegistration registration =
                createSignedRegistration(stateWithValidator, validatorKeyPair, 1, commitment);

        final BeaconBlock block =
                createBlock(
                        UInt64.ZERO,
                        UInt64.valueOf(spec.getBeaconProposerIndex(stateWithValidator, UInt64.ZERO)),
                        BLSSignature.infinity(),
                        Bytes32.ZERO,
                        registration);

        final SignedBeaconBlock signedBlock =
                spec.getGenesisSchemaDefinitions().getSignedBeaconBlockSchema().create(block, BLSSignature.empty());

        final BlockValidationResult result =
                blockProcessor.validateBlockPreProcessing(
                        stateWithValidator, signedBlock, BLSSignatureVerifier.SIMPLE);

        assertThat(result.isValid()).isTrue();
    }

    @Test
    void processOperationsNoValidation_withRegistrations_shouldAppendPendingCommitment() throws Exception {
        final BeaconStateEip8321 state = createStateWithProposer(proposerKeyPair, Bytes32.ZERO);
        final BLSKeyPair validatorKeyPair = BLSTestUtil.randomKeyPair(100);
        final BeaconStateEip8321 stateWithValidator = setValidatorPubKey(state, 1, validatorKeyPair);

        final Bytes32 commitment = dataStructureUtil.randomBytes32();
        final SignedRandaoCommitmentRegistration registration =
                createSignedRegistration(stateWithValidator, validatorKeyPair, 1, commitment);

        final BeaconBlockBody body =
                createBlockBody(BLSSignature.infinity(), Bytes32.ZERO, registration);

        final MutableBeaconStateEip8321 mutableState = stateWithValidator.createWritableCopy();
        blockProcessor.processOperationsNoValidation(
                mutableState,
                body,
                IndexedAttestationCache.NOOP,
                () -> null,
                UInt64.ZERO);

        final UInt64 expectedActivationEpoch =
                spec.computeEpochAtSlot(mutableState.getSlot())
                        .plus(spec.getGenesisSpecConfig().toVersionEip8321().orElseThrow().getCommitmentRegistrationDelay());

        assertThat(mutableState.getPendingRandaoCommitments()).hasSize(1);
        assertThat(mutableState.getPendingRandaoCommitments().get(0).getValidatorIndex())
                .isEqualTo(UInt64.valueOf(1));
        assertThat(mutableState.getPendingRandaoCommitments().get(0).getCommitment())
                .isEqualTo(commitment);
        assertThat(mutableState.getPendingRandaoCommitments().get(0).getActivationEpoch())
                .isEqualTo(expectedActivationEpoch);
    }

    @Test
    void processOperationsNoValidation_invalidRegistration_shouldThrowBlockProcessingException() {
        final BeaconStateEip8321 state = createStateWithProposer(proposerKeyPair, Bytes32.ZERO);
        final BLSKeyPair validatorKeyPair = BLSTestUtil.randomKeyPair(100);
        final BLSKeyPair wrongKeyPair = BLSTestUtil.randomKeyPair(101);
        final BeaconStateEip8321 stateWithValidator = setValidatorPubKey(state, 1, validatorKeyPair);

        final SignedRandaoCommitmentRegistration badRegistration =
                createSignedRegistration(stateWithValidator, wrongKeyPair, 1, dataStructureUtil.randomBytes32());

        final BeaconBlockBody body =
                createBlockBody(BLSSignature.infinity(), Bytes32.ZERO, badRegistration);

        final MutableBeaconStateEip8321 mutableState = stateWithValidator.createWritableCopy();

        assertThatThrownBy(
                () ->
                        blockProcessor.processOperationsNoValidation(
                                mutableState,
                                body,
                                IndexedAttestationCache.NOOP,
                                () -> null,
                                UInt64.ZERO))
                .isInstanceOf(BlockProcessingException.class)
                .hasMessageContaining("RandaoCommitmentRegistration signature is invalid");
    }

    private BeaconStateEip8321 setValidatorPubKey(
            final BeaconStateEip8321 state, final int validatorIndex, final BLSKeyPair keyPair) {
        return state.updatedEip8321(
                mutableState -> {
                    final Validator current = mutableState.getValidators().get(validatorIndex);
                    final Validator updated =
                            new Validator(
                                    keyPair.getPublicKey(),
                                    current.getWithdrawalCredentials(),
                                    current.getEffectiveBalance(),
                                    current.isSlashed(),
                                    current.getActivationEligibilityEpoch(),
                                    current.getActivationEpoch(),
                                    current.getExitEpoch(),
                                    current.getWithdrawableEpoch());
                    mutableState.getValidators().set(validatorIndex, updated);
                });
    }

    private SignedRandaoCommitmentRegistration createSignedRegistration(
            final BeaconState state,
            final BLSKeyPair keyPair,
            final int validatorIndex,
            final Bytes32 commitment) {
        final RandaoCommitmentRegistration registration =
                new RandaoCommitmentRegistration(UInt64.valueOf(validatorIndex), commitment);
        final Bytes32 domain =
                spec.getGenesisSpec()
                        .miscHelpers()
                        .computeDomain(Domain.DOMAIN_RANDAO_COMMITMENT_REGISTRATION, state.getGenesisValidatorsRoot());
        final Bytes signingRoot =
                spec.getGenesisSpec().miscHelpers().computeSigningRoot(registration, domain);
        final BLSSignature signature = BLS.sign(keyPair.getSecretKey(), signingRoot);
        return new SignedRandaoCommitmentRegistration(registration, signature);
    }

    private SszList<SignedRandaoCommitmentRegistration> createRegistrationsList(
            final SignedRandaoCommitmentRegistration... registrations) {
        final BeaconBlockBodySchemaEip8321<?> schema =
                (BeaconBlockBodySchemaEip8321<?>)
                        spec.getGenesisSchemaDefinitions().getBeaconBlockBodySchema();
        return schema.getRandaoCommitmentRegistrationsSchema().of(registrations);
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
            final Bytes32 hashChainReveal,
            final SignedRandaoCommitmentRegistration... registrations) {
        final BeaconBlockBody body = createBlockBody(randaoReveal, hashChainReveal, registrations);
        return new BeaconBlock(
                spec.getGenesisSchemaDefinitions().getBeaconBlockSchema(),
                slot,
                proposerIndex,
                dataStructureUtil.randomBytes32(),
                dataStructureUtil.randomBytes32(),
                body);
    }

    private BeaconBlockBody createBlockBody(
            final BLSSignature randaoReveal,
            final Bytes32 hashChainReveal,
            final SignedRandaoCommitmentRegistration... registrations) {
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
                                                            0))
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
                                                    schema.getBlsToExecutionChangesSchema().of())
                                            .signedExecutionPayloadBid(
                                                    dataStructureUtil.randomSignedExecutionPayloadBid())
                                            .payloadAttestations(
                                                    dataStructureUtil.randomSszList(
                                                            schema.getPayloadAttestationsSchema(),
                                                            dataStructureUtil::randomPayloadAttestation,
                                                            0))
                                            .parentExecutionRequests(dataStructureUtil.randomExecutionRequests());
                                    eip8321Builder.hashChainReveal(hashChainReveal);
                                    if (registrations.length > 0) {
                                        eip8321Builder.randaoCommitmentRegistrations(
                                                schema.getRandaoCommitmentRegistrationsSchema().of(registrations));
                                    } else {
                                        eip8321Builder.randaoCommitmentRegistrations(
                                                schema.getRandaoCommitmentRegistrationsSchema().of());
                                    }
                                    return SafeFuture.COMPLETE;
                                })
                        .join();
    }
}
