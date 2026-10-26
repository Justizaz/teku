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

import com.google.errorprone.annotations.CheckReturnValue;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

import org.apache.tuweni.bytes.Bytes32;
import tech.pegasys.teku.bls.BLSSignature;
import tech.pegasys.teku.bls.BLSSignatureVerifier;
import tech.pegasys.teku.infrastructure.crypto.Hash;
import tech.pegasys.teku.infrastructure.ssz.SszList;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszBytes32;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.cache.IndexedAttestationCache;
import tech.pegasys.teku.spec.config.SpecConfigEip8321;
import tech.pegasys.teku.spec.datastructures.blocks.BeaconBlock;
import tech.pegasys.teku.spec.datastructures.blocks.SignedBeaconBlock;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.BeaconBlockBody;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.versions.eip8321.BeaconBlockBodyEip8321;
import tech.pegasys.teku.spec.datastructures.execution.ExecutionRequestsDataCodec;
import tech.pegasys.teku.spec.datastructures.operations.Deposit;
import tech.pegasys.teku.spec.datastructures.operations.PendingRandaoCommitment;
import tech.pegasys.teku.spec.datastructures.operations.RandaoCommitmentRegistration;
import tech.pegasys.teku.spec.datastructures.operations.SignedRandaoCommitmentRegistration;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.MutableBeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.BeaconStateEip8321;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.MutableBeaconStateEip8321;
import tech.pegasys.teku.spec.logic.common.helpers.BeaconStateMutators;
import tech.pegasys.teku.spec.logic.common.operations.OperationSignatureVerifier;
import tech.pegasys.teku.spec.logic.common.operations.validation.OperationInvalidReason;
import tech.pegasys.teku.spec.logic.common.operations.validation.OperationValidator;
import tech.pegasys.teku.spec.logic.common.statetransition.blockvalidator.BlockValidationResult;
import tech.pegasys.teku.spec.logic.common.statetransition.exceptions.BlockProcessingException;
import tech.pegasys.teku.spec.logic.common.util.BeaconStateUtil;
import tech.pegasys.teku.spec.logic.common.util.HashChainRandaoUtil;
import tech.pegasys.teku.spec.logic.common.util.SyncCommitteeUtil;
import tech.pegasys.teku.spec.logic.common.util.ValidatorsUtil;
import tech.pegasys.teku.spec.logic.versions.gloas.execution.ExecutionRequestsProcessorGloas;
import tech.pegasys.teku.spec.logic.versions.gloas.helpers.BeaconStateAccessorsGloas;
import tech.pegasys.teku.spec.logic.versions.gloas.helpers.BeaconStateMutatorsGloas;
import tech.pegasys.teku.spec.logic.versions.gloas.helpers.MiscHelpersGloas;
import tech.pegasys.teku.spec.logic.versions.gloas.helpers.PredicatesGloas;
import tech.pegasys.teku.spec.logic.versions.gloas.util.AttestationUtilGloas;
import tech.pegasys.teku.spec.logic.versions.gloas.withdrawals.WithdrawalsHelpersGloas;
import tech.pegasys.teku.spec.logic.versions.heze.block.BlockProcessorHeze;
import tech.pegasys.teku.spec.schemas.SchemaDefinitionsEip8321;

public class BlockProcessorEip8321 extends BlockProcessorHeze {

    private final SpecConfigEip8321 specConfigEip8321;

    public BlockProcessorEip8321(
            final SpecConfigEip8321 specConfig,
            final PredicatesGloas predicates,
            final MiscHelpersGloas miscHelpers,
            final SyncCommitteeUtil syncCommitteeUtil,
            final BeaconStateAccessorsGloas beaconStateAccessors,
            final BeaconStateMutatorsGloas beaconStateMutators,
            final OperationSignatureVerifier operationSignatureVerifier,
            final BeaconStateUtil beaconStateUtil,
            final AttestationUtilGloas attestationUtil,
            final ValidatorsUtil validatorsUtil,
            final OperationValidator operationValidator,
            final SchemaDefinitionsEip8321 schemaDefinitions,
            final WithdrawalsHelpersGloas withdrawalsHelpers,
            final ExecutionRequestsDataCodec executionRequestsDataCodec,
            final ExecutionRequestsProcessorGloas executionRequestsProcessor) {
        super(
                specConfig,
                predicates,
                miscHelpers,
                syncCommitteeUtil,
                beaconStateAccessors,
                beaconStateMutators,
                operationSignatureVerifier,
                beaconStateUtil,
                attestationUtil,
                validatorsUtil,
                operationValidator,
                schemaDefinitions,
                withdrawalsHelpers,
                executionRequestsDataCodec,
                executionRequestsProcessor);
        this.specConfigEip8321 = specConfig;
    }

    @Override
    @CheckReturnValue
    protected BlockValidationResult validateBlockPreProcessing(
            final BeaconState preState,
            final SignedBeaconBlock block,
            final BLSSignatureVerifier signatureVerifier)
            throws BlockProcessingException {
        final BlockValidationResult superResult =
                super.validateBlockPreProcessing(preState, block, signatureVerifier);
        if (!superResult.isValid()) {
            return superResult;
        }

        final BeaconBlockBody blockBody = block.getMessage().getBody();
        if (blockBody instanceof BeaconBlockBodyEip8321 eip8321Body) {
            final SszList<SignedRandaoCommitmentRegistration> registrations =
                    eip8321Body.getRandaoCommitmentRegistrations();
            if (!registrations.isEmpty()) {
                return verifyRandaoCommitmentRegistrationsPreProcessing(
                        preState, registrations, signatureVerifier);
            }
        }

        return BlockValidationResult.SUCCESSFUL;
    }

    public BlockValidationResult verifyRandaoCommitmentRegistrationsPreProcessing(
            final BeaconState state,
            final SszList<SignedRandaoCommitmentRegistration> signedRegistrations,
            final BLSSignatureVerifier signatureVerifier) {
        final Set<UInt64> validatorsSeenInBlock = new HashSet<>();
        for (final SignedRandaoCommitmentRegistration signedRegistration : signedRegistrations) {
            final RandaoCommitmentRegistration registration = signedRegistration.getMessage();
            final UInt64 validatorIndex = registration.getValidatorIndex();

            if (!validatorsSeenInBlock.add(validatorIndex)) {
                return BlockValidationResult.failed(
                        "Duplicated RandaoCommitmentRegistration for validator " + validatorIndex);
            }

            final Optional<OperationInvalidReason> operationInvalidReason =
                    operationValidator.validateRandaoCommitmentRegistration(
                            state.getFork(), state, registration);
            if (operationInvalidReason.isPresent()) {
                return BlockValidationResult.failed(operationInvalidReason.get().describe());
            }

            final boolean signatureValid =
                    operationSignatureVerifier.verifyRandaoCommitmentRegistrationSignature(
                            state, signedRegistration, signatureVerifier);
            if (!signatureValid) {
                return BlockValidationResult.failed(
                        "RandaoCommitmentRegistration signature is invalid: " + signedRegistration);
            }
        }
        return BlockValidationResult.SUCCESSFUL;
    }

    @Override
    protected void processOperationsNoValidation(
            final MutableBeaconState state,
            final BeaconBlockBody body,
            final IndexedAttestationCache indexedAttestationCache,
            final Supplier<BeaconStateMutators.ValidatorExitContext> validatorExitContextSupplier,
            final UInt64 parentSlot)
            throws BlockProcessingException {
        super.processOperationsNoValidation(
                state, body, indexedAttestationCache, validatorExitContextSupplier, parentSlot);

        if (body instanceof BeaconBlockBodyEip8321 eip8321Body) {
            safelyProcess(
                    () ->
                            processRandaoCommitmentRegistrations(
                                    state, eip8321Body.getRandaoCommitmentRegistrations()));
        }
    }

    public void processRandaoCommitmentRegistrations(
            final MutableBeaconState state,
            final SszList<SignedRandaoCommitmentRegistration> registrations)
            throws BlockProcessingException {
        final BlockValidationResult result =
                verifyRandaoCommitmentRegistrationsPreProcessing(
                        state, registrations, BLSSignatureVerifier.SIMPLE);
        if (!result.isValid()) {
            throw new BlockProcessingException(result.getFailureReason());
        }

        final MutableBeaconStateEip8321 stateEip8321 = MutableBeaconStateEip8321.required(state);
        final UInt64 currentEpoch = beaconStateAccessors.getCurrentEpoch(state);
        final UInt64 activationEpoch =
                currentEpoch.plus(specConfigEip8321.getCommitmentRegistrationDelay());

        for (final SignedRandaoCommitmentRegistration signedRegistration : registrations) {
            final RandaoCommitmentRegistration registration = signedRegistration.getMessage();
            final PendingRandaoCommitment pending =
                    new PendingRandaoCommitment(
                            registration.getValidatorIndex(),
                            registration.getCommitment(),
                            activationEpoch);
            stateEip8321.getPendingRandaoCommitments().append(pending);
        }
    }

    @Override
    protected BlockValidationResult verifyRandao(
            final BeaconState state, final BeaconBlock block, final BLSSignatureVerifier bls) {
        final Optional<BeaconStateEip8321> stateEip8321 = state.toVersionEip8321();
        if (stateEip8321.isPresent()) {
            final int proposerIndex = block.getProposerIndex().intValue();
            final Bytes32 currentCommitment =
                    stateEip8321.get().getRandaoCommitments().get(proposerIndex).get();
            final BeaconBlockBody body = block.getBody();
            final Bytes32 hashChainReveal =
                    (body instanceof BeaconBlockBodyEip8321 eip8321Body)
                            ? eip8321Body.getHashChainReveal()
                            : Bytes32.ZERO;

            if (!currentCommitment.isZero()) {
                if (hashChainReveal.isZero()) {
                    return BlockValidationResult.failed("Hash chain reveal is zero.");
                }
                if (!HashChainRandaoUtil.verifyReveal(currentCommitment, hashChainReveal)) {
                    return BlockValidationResult.failed("Hash chain reveal is invalid.");
                }
                if (!body.getRandaoReveal().equals(BLSSignature.infinity())) {
                    return BlockValidationResult.failed(
                            "Expected BLS signature at infinity for hash chain reveal.");
                }
                return BlockValidationResult.SUCCESSFUL;
            } else {
                if (!hashChainReveal.isZero()) {
                    return BlockValidationResult.failed(
                            "Expected zero hash chain reveal for legacy RANDAO.");
                }
            }
        }
        return super.verifyRandao(state, block, bls);
    }

    @Override
    protected void processRandaoNoValidation(
            final MutableBeaconState state, final BeaconBlockBody body) throws BlockProcessingException {
        final Optional<MutableBeaconStateEip8321> stateEip8321 = state.toMutableVersionEip8321();
        if (stateEip8321.isPresent()) {
            safelyProcess(
                    () -> {
                        final UInt64 epoch = beaconStateAccessors.getCurrentEpoch(state);
                        final int proposerIndex = beaconStateAccessors.getBeaconProposerIndex(state);
                        final Bytes32 currentCommitment =
                                stateEip8321.get().getRandaoCommitments().get(proposerIndex).get();

                        if (!currentCommitment.isZero()) {
                            final Bytes32 hashChainReveal =
                                    BeaconBlockBodyEip8321.required(body).getHashChainReveal();
                            final Bytes32 currentMix = beaconStateAccessors.getRandaoMix(state, epoch);
                            final Bytes32 newMix = HashChainRandaoUtil.computeNextMix(currentMix, hashChainReveal);

                            stateEip8321
                                    .get()
                                    .getRandaoCommitments()
                                    .set(proposerIndex, SszBytes32.of(hashChainReveal));
                            final int mixIndex =
                                    epoch.mod(specConfig.getEpochsPerHistoricalVector()).intValue();
                            state.getRandaoMixes().setElement(mixIndex, newMix);
                            return;
                        }

                        final Bytes32 mix =
                                beaconStateAccessors
                                        .getRandaoMix(state, epoch)
                                        .xor(Hash.sha256(body.getRandaoReveal().toSSZBytes()));
                        final int index = epoch.mod(specConfig.getEpochsPerHistoricalVector()).intValue();
                        state.getRandaoMixes().setElement(index, mix);
                    });
            return;
        }

        super.processRandaoNoValidation(state, body);
    }
}
