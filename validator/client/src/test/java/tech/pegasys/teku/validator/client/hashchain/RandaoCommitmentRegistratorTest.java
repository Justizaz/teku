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

package tech.pegasys.teku.validator.client.hashchain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tech.pegasys.teku.bls.BLS;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSPublicKey;
import tech.pegasys.teku.infrastructure.async.SafeFuture;
import tech.pegasys.teku.infrastructure.async.StubAsyncRunner;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.Spec;
import tech.pegasys.teku.spec.TestSpecFactory;
import tech.pegasys.teku.spec.constants.Domain;
import tech.pegasys.teku.spec.datastructures.operations.SignedRandaoCommitmentRegistration;
import tech.pegasys.teku.spec.signatures.LocalSigner;
import tech.pegasys.teku.spec.signatures.Signer;
import tech.pegasys.teku.spec.util.DataStructureUtil;
import tech.pegasys.teku.validator.api.ValidatorApiChannel;
import tech.pegasys.teku.validator.beaconnode.GenesisDataProvider;
import tech.pegasys.teku.validator.client.Validator;
import tech.pegasys.teku.validator.client.ValidatorIndexProvider;

class RandaoCommitmentRegistratorTest {

  private final Spec spec = TestSpecFactory.createMinimalEip8321();
  private final DataStructureUtil dataStructureUtil = new DataStructureUtil(spec);
  private final StubAsyncRunner asyncRunner = new StubAsyncRunner();

  private final ValidatorApiChannel validatorApiChannel = mock(ValidatorApiChannel.class);
  private final ValidatorIndexProvider validatorIndexProvider = mock(ValidatorIndexProvider.class);
  private final GenesisDataProvider genesisDataProvider = mock(GenesisDataProvider.class);

  private final HashChainGenerator hashChainGenerator = new HashChainGenerator();

  private BLSKeyPair keyPair;
  private Validator validator;
  private HashChain hashChain;
  private HashChainStore hashChainStore;
  private RandaoCommitmentRegistrator registrator;

  @BeforeEach
  void setUp(@TempDir final Path tempDir) {
    keyPair = dataStructureUtil.randomKeyPair();
    final Signer signer = new LocalSigner(spec, keyPair, asyncRunner);
    validator = new Validator(keyPair.getPublicKey(), signer, Optional::empty);
    hashChain = hashChainGenerator.generate(10);
    hashChainStore = new HashChainStore(tempDir, 1000);

    registrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel, validatorIndexProvider, genesisDataProvider, hashChainStore);

    when(validatorApiChannel.sendSignedRandaoCommitmentRegistration(any()))
        .thenReturn(SafeFuture.COMPLETE);
  }

  @Test
  void createSignedRegistration_shouldConstructCorrectRegistrationAndSignature() {
    final UInt64 validatorIndex = UInt64.valueOf(42);
    final Bytes32 commitment = hashChain.getCommitment();
    final Bytes32 genesisValidatorsRoot = dataStructureUtil.randomBytes32();

    final SafeFuture<SignedRandaoCommitmentRegistration> future =
        registrator.createSignedRegistration(
            validator, validatorIndex, commitment, genesisValidatorsRoot);
    asyncRunner.executeQueuedActions();

    assertThat(future).isCompleted();
    final SignedRandaoCommitmentRegistration signedRegistration = future.join();
    assertThat(signedRegistration.getMessage().getValidatorIndex()).isEqualTo(validatorIndex);
    assertThat(signedRegistration.getMessage().getCommitment()).isEqualTo(commitment);

    final Bytes32 domain =
        spec.getGenesisSpec()
            .miscHelpers()
            .computeDomain(Domain.DOMAIN_RANDAO_COMMITMENT_REGISTRATION, genesisValidatorsRoot);
    final Bytes signingRoot =
        spec.getGenesisSpec()
            .miscHelpers()
            .computeSigningRoot(signedRegistration.getMessage(), domain);

    assertThat(BLS.verify(keyPair.getPublicKey(), signingRoot, signedRegistration.getSignature()))
        .isTrue();
  }

  @Test
  void createSignedRegistrationWithHashChain_shouldResolveIndicesAndGenesisValidatorsRoot() {
    final Bytes32 genesisValidatorsRoot = dataStructureUtil.randomBytes32();
    final int expectedIndex = 17;

    when(genesisDataProvider.getGenesisValidatorsRoot())
        .thenReturn(SafeFuture.completedFuture(genesisValidatorsRoot));
    when(validatorIndexProvider.getValidatorIndicesByPublicKey())
        .thenReturn(SafeFuture.completedFuture(Map.of(keyPair.getPublicKey(), expectedIndex)));

    final SafeFuture<Optional<SignedRandaoCommitmentRegistration>> future =
        registrator.createSignedRegistration(validator, hashChain);
    asyncRunner.executeQueuedActions();

    assertThat(future).isCompleted();
    final Optional<SignedRandaoCommitmentRegistration> result = future.join();
    assertThat(result).isPresent();
    assertThat(result.get().getMessage().getValidatorIndex())
        .isEqualTo(UInt64.valueOf(expectedIndex));
    assertThat(result.get().getMessage().getCommitment()).isEqualTo(hashChain.getCommitment());
  }

  @Test
  void createSignedRegistrationWithHashChain_shouldReturnEmptyWhenValidatorIndexUnknown() {
    final Bytes32 genesisValidatorsRoot = dataStructureUtil.randomBytes32();

    when(genesisDataProvider.getGenesisValidatorsRoot())
        .thenReturn(SafeFuture.completedFuture(genesisValidatorsRoot));
    when(validatorIndexProvider.getValidatorIndicesByPublicKey())
        .thenReturn(SafeFuture.completedFuture(Map.of()));
    when(validatorApiChannel.getValidatorIndices(List.of(keyPair.getPublicKey())))
        .thenReturn(SafeFuture.completedFuture(Map.of()));

    final SafeFuture<Optional<SignedRandaoCommitmentRegistration>> future =
        registrator.createSignedRegistration(validator, hashChain);
    asyncRunner.executeQueuedActions();

    assertThat(future).isCompleted();
    assertThat(future.join()).isEmpty();
  }

  @Test
  void createSignedRegistrationWithHashChain_shouldFallbackToApiWhenIndexProviderEmpty() {
    final Bytes32 genesisValidatorsRoot = dataStructureUtil.randomBytes32();
    final int fallbackIndex = 88;

    when(genesisDataProvider.getGenesisValidatorsRoot())
        .thenReturn(SafeFuture.completedFuture(genesisValidatorsRoot));
    when(validatorIndexProvider.getValidatorIndicesByPublicKey())
        .thenReturn(SafeFuture.completedFuture(Map.of()));
    when(validatorApiChannel.getValidatorIndices(List.of(keyPair.getPublicKey())))
        .thenReturn(SafeFuture.completedFuture(Map.of(keyPair.getPublicKey(), fallbackIndex)));

    final SafeFuture<Optional<SignedRandaoCommitmentRegistration>> future =
        registrator.createSignedRegistration(validator, hashChain);
    asyncRunner.executeQueuedActions();

    assertThat(future).isCompleted();
    final Optional<SignedRandaoCommitmentRegistration> result = future.join();
    assertThat(result).isPresent();
    assertThat(result.get().getMessage().getValidatorIndex())
        .isEqualTo(UInt64.valueOf(fallbackIndex));
  }

  @Test
  void submitRegistration_shouldCallValidatorApiChannel() {
    final SignedRandaoCommitmentRegistration signedRegistration =
        dataStructureUtil.randomSignedRandaoCommitmentRegistration();

    final SafeFuture<Void> future = registrator.submitRegistration(signedRegistration);

    assertThat(future).isCompleted();
    verify(validatorApiChannel).sendSignedRandaoCommitmentRegistration(signedRegistration);
  }

  @Test
  void registerValidator_shouldCreateAndSubmitSuccessfully() {
    final Bytes32 genesisValidatorsRoot = dataStructureUtil.randomBytes32();
    final int validatorIndex = 5;

    when(genesisDataProvider.getGenesisValidatorsRoot())
        .thenReturn(SafeFuture.completedFuture(genesisValidatorsRoot));
    when(validatorIndexProvider.getValidatorIndicesByPublicKey())
        .thenReturn(SafeFuture.completedFuture(Map.of(keyPair.getPublicKey(), validatorIndex)));

    final SafeFuture<Boolean> future = registrator.registerValidator(validator, hashChain);
    asyncRunner.executeQueuedActions();

    assertThat(future).isCompleted();
    assertThat(future.join()).isTrue();
    assertThat(registrator.isAlreadySubmitted(keyPair.getPublicKey(), hashChain.getCommitment()))
        .isTrue();

    verify(validatorApiChannel).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void registerValidator_shouldSkipDuplicateSubmissionWhenAlreadySubmitted() {
    final Bytes32 genesisValidatorsRoot = dataStructureUtil.randomBytes32();
    final int validatorIndex = 5;

    when(genesisDataProvider.getGenesisValidatorsRoot())
        .thenReturn(SafeFuture.completedFuture(genesisValidatorsRoot));
    when(validatorIndexProvider.getValidatorIndicesByPublicKey())
        .thenReturn(SafeFuture.completedFuture(Map.of(keyPair.getPublicKey(), validatorIndex)));

    // First submission
    final SafeFuture<Boolean> firstFuture = registrator.registerValidator(validator, hashChain);
    asyncRunner.executeQueuedActions();
    assertThat(firstFuture).isCompleted();
    assertThat(firstFuture.join()).isTrue();
    verify(validatorApiChannel, times(1)).sendSignedRandaoCommitmentRegistration(any());

    // Second submission with same validator and commitment
    final SafeFuture<Boolean> secondFuture = registrator.registerValidator(validator, hashChain);
    asyncRunner.executeQueuedActions();
    assertThat(secondFuture).isCompleted();
    assertThat(secondFuture.join()).isTrue();
    // API is not invoked again
    verify(validatorApiChannel, times(1)).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void registerValidator_shouldHandleApiRejectionSafely() {
    final Bytes32 genesisValidatorsRoot = dataStructureUtil.randomBytes32();
    final int validatorIndex = 5;

    when(genesisDataProvider.getGenesisValidatorsRoot())
        .thenReturn(SafeFuture.completedFuture(genesisValidatorsRoot));
    when(validatorIndexProvider.getValidatorIndicesByPublicKey())
        .thenReturn(SafeFuture.completedFuture(Map.of(keyPair.getPublicKey(), validatorIndex)));
    when(validatorApiChannel.sendSignedRandaoCommitmentRegistration(any()))
        .thenReturn(
            SafeFuture.failedFuture(
                new IllegalArgumentException("Registration rejected: already pending")));

    final SafeFuture<Boolean> future = registrator.registerValidator(validator, hashChain);
    asyncRunner.executeQueuedActions();

    assertThat(future).isCompleted();
    assertThat(future.join()).isFalse();
    // Not marked as submitted so it can be retried later
    assertThat(registrator.isAlreadySubmitted(keyPair.getPublicKey(), hashChain.getCommitment()))
        .isFalse();
  }

  @Test
  void registerValidator_shouldHandleUnknownValidatorIndexSafely() {
    final Bytes32 genesisValidatorsRoot = dataStructureUtil.randomBytes32();

    when(genesisDataProvider.getGenesisValidatorsRoot())
        .thenReturn(SafeFuture.completedFuture(genesisValidatorsRoot));
    when(validatorIndexProvider.getValidatorIndicesByPublicKey())
        .thenReturn(SafeFuture.completedFuture(Map.of()));
    when(validatorApiChannel.getValidatorIndices(List.of(keyPair.getPublicKey())))
        .thenReturn(SafeFuture.completedFuture(Map.of()));

    final SafeFuture<Boolean> future = registrator.registerValidator(validator, hashChain);
    asyncRunner.executeQueuedActions();

    assertThat(future).isCompleted();
    assertThat(future.join()).isFalse();
    verify(validatorApiChannel, never()).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void registerValidator_shouldHandleGenesisDataFailureSafely() {
    when(genesisDataProvider.getGenesisValidatorsRoot())
        .thenReturn(SafeFuture.failedFuture(new RuntimeException("Genesis not known")));

    final SafeFuture<Boolean> future = registrator.registerValidator(validator, hashChain);
    asyncRunner.executeQueuedActions();

    assertThat(future).isCompleted();
    assertThat(future.join()).isFalse();
    verify(validatorApiChannel, never()).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void registerValidatorWithPassword_shouldLoadFromStoreAndSubmit() {
    final String password = "testPassword123!";
    hashChainStore.storeHashChain(keyPair.getPublicKey(), hashChain, password);

    final Bytes32 genesisValidatorsRoot = dataStructureUtil.randomBytes32();
    final int validatorIndex = 12;

    when(genesisDataProvider.getGenesisValidatorsRoot())
        .thenReturn(SafeFuture.completedFuture(genesisValidatorsRoot));
    when(validatorIndexProvider.getValidatorIndicesByPublicKey())
        .thenReturn(SafeFuture.completedFuture(Map.of(keyPair.getPublicKey(), validatorIndex)));

    final SafeFuture<Boolean> future = registrator.registerValidator(validator, password);
    asyncRunner.executeQueuedActions();

    assertThat(future).isCompleted();
    assertThat(future.join()).isTrue();
    verify(validatorApiChannel).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void registerValidatorWithPassword_shouldHandleMissingOrCorruptedStoreChain() {
    // No stored chain
    final SafeFuture<Boolean> missingFuture =
        registrator.registerValidator(validator, "somePassword");
    assertThat(missingFuture).isCompleted();
    assertThat(missingFuture.join()).isFalse();

    // Stored chain but wrong password
    hashChainStore.storeHashChain(keyPair.getPublicKey(), hashChain, "correctPassword");
    final SafeFuture<Boolean> wrongPasswordFuture =
        registrator.registerValidator(validator, "wrongPassword");
    assertThat(wrongPasswordFuture).isCompleted();
    assertThat(wrongPasswordFuture.join()).isFalse();
  }

  @Test
  void registerValidators_shouldProcessMultipleValidators() {
    final BLSKeyPair keyPair2 = dataStructureUtil.randomKeyPair();
    final Signer signer2 = new LocalSigner(spec, keyPair2, asyncRunner);
    final Validator validator2 = new Validator(keyPair2.getPublicKey(), signer2, Optional::empty);
    final HashChain hashChain2 = hashChainGenerator.generate(10);

    final Bytes32 genesisValidatorsRoot = dataStructureUtil.randomBytes32();

    when(genesisDataProvider.getGenesisValidatorsRoot())
        .thenReturn(SafeFuture.completedFuture(genesisValidatorsRoot));
    when(validatorIndexProvider.getValidatorIndicesByPublicKey())
        .thenReturn(
            SafeFuture.completedFuture(
                Map.of(keyPair.getPublicKey(), 1, keyPair2.getPublicKey(), 2)));

    final SafeFuture<Map<BLSPublicKey, Boolean>> future =
        registrator.registerValidators(
            List.of(validator, validator2),
            Map.of(keyPair.getPublicKey(), hashChain, keyPair2.getPublicKey(), hashChain2));
    asyncRunner.executeQueuedActions();

    assertThat(future).isCompleted();
    final Map<BLSPublicKey, Boolean> results = future.join();
    assertThat(results).containsEntry(keyPair.getPublicKey(), true);
    assertThat(results).containsEntry(keyPair2.getPublicKey(), true);
  }
}
