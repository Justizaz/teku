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

package tech.pegasys.teku.spec.logic.versions.heze.block;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.config.SpecConfigHeze;
import tech.pegasys.teku.spec.datastructures.blocks.BeaconBlock;
import tech.pegasys.teku.spec.datastructures.blocks.BeaconBlockSummary;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.versions.heze.BeaconBlockBodyHeze;
import tech.pegasys.teku.spec.datastructures.operations.RandaoCommitmentRegistration;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.MutableBeaconState;
import tech.pegasys.teku.spec.logic.common.operations.OperationSignatureVerifier;
import tech.pegasys.teku.spec.logic.common.operations.validation.OperationValidator;
import tech.pegasys.teku.spec.logic.common.statetransition.exceptions.BlockProcessingException;
import tech.pegasys.teku.spec.logic.common.util.BeaconStateUtil;
import tech.pegasys.teku.spec.logic.common.util.SyncCommitteeUtil;
import tech.pegasys.teku.spec.logic.common.util.ValidatorsUtil;
import tech.pegasys.teku.spec.logic.versions.gloas.block.BlockProcessorGloas;
import tech.pegasys.teku.spec.logic.versions.gloas.execution.ExecutionRequestsProcessorGloas;
import tech.pegasys.teku.spec.logic.versions.gloas.helpers.BeaconStateAccessorsGloas;
import tech.pegasys.teku.spec.logic.versions.gloas.helpers.BeaconStateMutatorsGloas;
import tech.pegasys.teku.spec.logic.versions.gloas.helpers.MiscHelpersGloas;
import tech.pegasys.teku.spec.logic.versions.gloas.helpers.PredicatesGloas;
import tech.pegasys.teku.spec.logic.versions.gloas.util.AttestationUtilGloas;
import tech.pegasys.teku.spec.logic.versions.gloas.withdrawals.WithdrawalsHelpersGloas;
import tech.pegasys.teku.spec.datastructures.execution.ExecutionRequestsDataCodec;
import tech.pegasys.teku.spec.schemas.SchemaDefinitionsGloas;

public class BlockProcessorHeze extends BlockProcessorGloas {

    private static final Logger LOG = LogManager.getLogger();

    private final SpecConfigHeze specConfigHeze;

    public BlockProcessorHeze(
            final SpecConfigHeze specConfig,
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
            final SchemaDefinitionsGloas schemaDefinitions,
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
        this.specConfigHeze = specConfig;
    }

    @Override
    public void processBlockHeader(
            final MutableBeaconState state, final BeaconBlockSummary blockSummary)
            throws BlockProcessingException {
        super.processBlockHeader(state, blockSummary);

        if (blockSummary instanceof BeaconBlock) {
            final BeaconBlock block = (BeaconBlock) blockSummary;
            if (block.getBody() instanceof BeaconBlockBodyHeze) {
                final BeaconBlockBodyHeze hezeBody = (BeaconBlockBodyHeze) block.getBody();
                processRandaoCommitmentRegistrations(state, hezeBody.getRandaoCommitmentRegistrations());
            }
        }
    }

    private void processRandaoCommitmentRegistrations(
            final BeaconState state,
            final Iterable<RandaoCommitmentRegistration> registrations)
            throws BlockProcessingException {
        for (final RandaoCommitmentRegistration registration : registrations) {
            validateRandaoCommitmentRegistration(state, registration);
        }
    }

    private void validateRandaoCommitmentRegistration(
            final BeaconState state, final RandaoCommitmentRegistration registration)
            throws BlockProcessingException {
        final UInt64 validatorIndex = registration.getValidatorIndex();

        if (validatorIndex.isGreaterThanOrEqualTo(state.getValidators().size())) {
            throw new BlockProcessingException("Invalid validator index for RandaoCommitmentRegistration");
        }
    }
}