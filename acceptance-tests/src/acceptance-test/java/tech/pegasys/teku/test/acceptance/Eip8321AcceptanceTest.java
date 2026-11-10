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

package tech.pegasys.teku.test.acceptance;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.util.List;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tech.pegasys.teku.bls.BLS;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSSignature;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.versions.eip8321.BeaconBlockBodyEip8321;
import tech.pegasys.teku.spec.datastructures.interop.MockStartValidatorKeyPairFactory;
import tech.pegasys.teku.spec.datastructures.operations.RandaoCommitmentRegistration;
import tech.pegasys.teku.spec.datastructures.operations.SignedRandaoCommitmentRegistration;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.BeaconStateEip8321;
import tech.pegasys.teku.spec.signatures.SigningRootUtil;
import tech.pegasys.teku.test.acceptance.dsl.AcceptanceTestBase;
import tech.pegasys.teku.test.acceptance.dsl.GenesisGenerator.InitialStateData;
import tech.pegasys.teku.test.acceptance.dsl.TekuBeaconNode;
import tech.pegasys.teku.test.acceptance.dsl.TekuNodeConfigBuilder;
import tech.pegasys.teku.test.acceptance.dsl.tools.deposits.ValidatorKeystores;
import tech.pegasys.teku.validator.client.hashchain.HashChain;
import tech.pegasys.teku.validator.client.hashchain.HashChainGenerator;
import tech.pegasys.teku.validator.client.hashchain.HashChainStore;

public class Eip8321AcceptanceTest extends AcceptanceTestBase {

  private static final String NETWORK_NAME = "swift";

  @Test
  void shouldExecuteCompleteEip8321ValidatorWorkflow(@TempDir final Path tempDir) throws Exception {
    final int validatorCount = 4;
    final int targetValidatorIndex = 0;
    final int unregisteredValidatorIndex = 1;

    final ValidatorKeystores validatorKeystores =
        createValidatorKeyGenerator().generateValidatorKeys(validatorCount);

    final List<BLSKeyPair> interopKeyPairs =
        new MockStartValidatorKeyPairFactory().generateKeyPairs(0, validatorCount);
    final BLSKeyPair targetValidatorKeyPair = interopKeyPairs.get(targetValidatorIndex);

    final InitialStateData genesis =
        createGenesisGenerator()
            .network(NETWORK_NAME)
            .validatorKeys(validatorKeystores)
            .withAltairEpoch(UInt64.ZERO)
            .withBellatrixEpoch(UInt64.ZERO)
            .withCapellaEpoch(UInt64.ZERO)
            .withDenebEpoch(UInt64.ZERO)
            .withElectraEpoch(UInt64.ZERO)
            .withFuluEpoch(UInt64.ZERO)
            .withGloasEpoch(UInt64.ZERO)
            .withHezeEpoch(UInt64.ZERO)
            .withEip8321Epoch(UInt64.ZERO)
            .generate();

    final TekuBeaconNode beaconNode =
        createTekuBeaconNode(
            TekuNodeConfigBuilder.createBeaconNode()
                .withNetwork(NETWORK_NAME)
                .withInitialState(genesis)
                .withAltairEpoch(UInt64.ZERO)
                .withBellatrixEpoch(UInt64.ZERO)
                .withCapellaEpoch(UInt64.ZERO)
                .withDenebEpoch(UInt64.ZERO)
                .withElectraEpoch(UInt64.ZERO)
                .withFuluEpoch(UInt64.ZERO)
                .withGloasEpoch(UInt64.ZERO)
                .withHezeEpoch(UInt64.ZERO)
                .withEip8321Epoch(UInt64.ZERO)
                .withReadOnlyKeystorePath(validatorKeystores)
                .build());

    // 1. Generate and store a hash chain
    final HashChain hashChain = new HashChainGenerator().generate(65536);
    final Bytes32 commitment = hashChain.getCommitment();
    final HashChainStore hashChainStore = new HashChainStore(tempDir);
    hashChainStore.storeHashChain(
        targetValidatorKeyPair.getPublicKey(), hashChain, "test-password");

    assertThat(hashChainStore.hasHashChain(targetValidatorKeyPair.getPublicKey())).isTrue();
    final HashChain loadedChain =
        hashChainStore
            .loadHashChain(targetValidatorKeyPair.getPublicKey(), "test-password")
            .orElseThrow();
    assertThat(loadedChain.getCommitment()).isEqualTo(commitment);

    beaconNode.start();
    beaconNode.waitForGenesis();

    // 2. Sign and submit commitment registration through the Beacon API
    final Bytes32 genesisValidatorsRoot = beaconNode.getGenesisValidatorsRoot();
    final RandaoCommitmentRegistration registrationMessage =
        new RandaoCommitmentRegistration(UInt64.valueOf(targetValidatorIndex), commitment);

    final SigningRootUtil signingRootUtil = new SigningRootUtil(beaconNode.getSpec());
    final Bytes signingRoot =
        signingRootUtil.signingRootForRandaoCommitmentRegistration(
            registrationMessage, genesisValidatorsRoot);
    final BLSSignature signature = BLS.sign(targetValidatorKeyPair.getSecretKey(), signingRoot);
    final SignedRandaoCommitmentRegistration signedRegistration =
        new SignedRandaoCommitmentRegistration(registrationMessage, signature);

    beaconNode.submitRandaoCommitmentRegistration(signedRegistration);

    // 3. Include registration in a block
    beaconNode.waitForBlockSatisfying(
        block -> {
          final BeaconBlockBodyEip8321 body =
              BeaconBlockBodyEip8321.required(block.getMessage().getBody());
          assertThat(body.getRandaoCommitmentRegistrations())
              .anyMatch(
                  reg ->
                      reg.getMessage()
                          .getValidatorIndex()
                          .equals(UInt64.valueOf(targetValidatorIndex)));
        });

    // 4. Advance the chain until the commitment activates (COMMITMENT_REGISTRATION_DELAY = 3
    // epochs)
    beaconNode.waitForEpochAtOrAbove(4);

    final BeaconStateEip8321 stateAfterActivation =
        BeaconStateEip8321.required(beaconNode.getHeadState());
    assertThat(stateAfterActivation.getRandaoCommitments().get(targetValidatorIndex).get())
        .isEqualTo(commitment);

    // 5. Propose a block using the correct hash-chain reveal and verify state commitment
    // advancement
    final Bytes32 expectedPreimage = loadedChain.getRevealForCommitment(commitment).orElseThrow();

    beaconNode.waitForBlockSatisfying(
        block -> {
          if (block.getMessage().getProposerIndex().equals(UInt64.valueOf(targetValidatorIndex))) {
            final BeaconBlockBodyEip8321 body =
                BeaconBlockBodyEip8321.required(block.getMessage().getBody());
            // Proposer must supply hash chain reveal and BLSSignature.infinity()
            assertThat(body.getHashChainReveal()).isEqualTo(expectedPreimage);
            assertThat(body.getRandaoReveal()).isEqualTo(BLSSignature.infinity());
          }
        });

    // 6. Verify commitment advances to preimage in state
    final BeaconStateEip8321 stateAfterReveal =
        BeaconStateEip8321.required(beaconNode.getHeadState());
    assertThat(stateAfterReveal.getRandaoCommitments().get(targetValidatorIndex).get())
        .isEqualTo(expectedPreimage);

    // 7. Verify an unregistered validator still uses legacy BLS RANDAO and zero hash chain reveal
    beaconNode.waitForBlockSatisfying(
        block -> {
          if (block
              .getMessage()
              .getProposerIndex()
              .equals(UInt64.valueOf(unregisteredValidatorIndex))) {
            final BeaconBlockBodyEip8321 body =
                BeaconBlockBodyEip8321.required(block.getMessage().getBody());
            assertThat(body.getHashChainReveal()).isEqualTo(Bytes32.ZERO);
            assertThat(body.getRandaoReveal()).isNotEqualTo(BLSSignature.infinity());
          }
        });

    final BeaconStateEip8321 finalState = BeaconStateEip8321.required(beaconNode.getHeadState());
    assertThat(finalState.getRandaoCommitments().get(unregisteredValidatorIndex).get())
        .isEqualTo(Bytes32.ZERO);
  }
}
