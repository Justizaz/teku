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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import tech.pegasys.teku.bls.BLS;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSPublicKey;
import tech.pegasys.teku.infrastructure.async.AsyncRunner;
import tech.pegasys.teku.infrastructure.async.AsyncRunnerFactory;
import tech.pegasys.teku.infrastructure.async.MetricTrackingExecutorFactory;
import tech.pegasys.teku.infrastructure.async.SafeFuture;
import tech.pegasys.teku.infrastructure.async.StubAsyncRunner;
import tech.pegasys.teku.infrastructure.metrics.StubMetricsSystem;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.Spec;
import tech.pegasys.teku.spec.TestSpecFactory;
import tech.pegasys.teku.spec.constants.Domain;
import tech.pegasys.teku.spec.datastructures.operations.SignedRandaoCommitmentRegistration;
import tech.pegasys.teku.spec.signatures.LocalSigner;
import tech.pegasys.teku.spec.signatures.Signer;
import tech.pegasys.teku.spec.util.DataStructureUtil;
import tech.pegasys.teku.validator.api.ValidatorApiChannel;
import tech.pegasys.teku.validator.api.ValidatorRandaoCommitmentStatus;
import tech.pegasys.teku.validator.beaconnode.GenesisDataProvider;
import tech.pegasys.teku.validator.client.Validator;
import tech.pegasys.teku.validator.client.ValidatorIndexProvider;
import tech.pegasys.teku.validator.client.loader.OwnedValidators;

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

  @Test
  void onSlot_shouldIgnoreSlotsBeforeEip8321Fork() {
    final Spec preForkSpec = TestSpecFactory.createMinimalAltair();
    final OwnedValidators ownedValidators =
        new OwnedValidators(Map.of(keyPair.getPublicKey(), validator));
    final RandaoCommitmentRegistrator preForkRegistrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            hashChainStore,
            ownedValidators,
            preForkSpec,
            asyncRunner);

    preForkRegistrator.onSlot(UInt64.valueOf(1));
    verify(validatorApiChannel, never()).getValidatorRandaoCommitmentStatus(any());
  }

  @Test
  void processRegistrations_shouldSkipWhenPoolRegistrationMatchesLocalChain() {
    final OwnedValidators ownedValidators =
        new OwnedValidators(Map.of(keyPair.getPublicKey(), validator));
    hashChainStore.storeHashChain(keyPair.getPublicKey(), hashChain, "");

    final RandaoCommitmentRegistrator autoRegistrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            hashChainStore,
            ownedValidators,
            spec,
            asyncRunner);

    final ValidatorRandaoCommitmentStatus status =
        new ValidatorRandaoCommitmentStatus(
            false,
            Optional.empty(),
            false,
            Optional.empty(),
            Optional.empty(),
            true,
            Optional.of(hashChain.getCommitment()));

    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPair.getPublicKey()))
        .thenReturn(SafeFuture.completedFuture(status));

    autoRegistrator.onSlot(UInt64.valueOf(10));
    asyncRunner.executeQueuedActions();

    assertThat(
            autoRegistrator.isAlreadySubmitted(keyPair.getPublicKey(), hashChain.getCommitment()))
        .isTrue();
    assertThat(autoRegistrator.isFaulty(keyPair.getPublicKey())).isFalse();
    verify(validatorApiChannel, never()).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void processRegistrations_shouldMarkFaultyWhenPoolRegistrationMismatchesLocalChain() {
    final OwnedValidators ownedValidators =
        new OwnedValidators(Map.of(keyPair.getPublicKey(), validator));
    hashChainStore.storeHashChain(keyPair.getPublicKey(), hashChain, "");

    final RandaoCommitmentRegistrator autoRegistrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            hashChainStore,
            ownedValidators,
            spec,
            asyncRunner);

    final Bytes32 differentCommitment = dataStructureUtil.randomBytes32();
    final ValidatorRandaoCommitmentStatus status =
        new ValidatorRandaoCommitmentStatus(
            false,
            Optional.empty(),
            false,
            Optional.empty(),
            Optional.empty(),
            true,
            Optional.of(differentCommitment));

    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPair.getPublicKey()))
        .thenReturn(SafeFuture.completedFuture(status));

    autoRegistrator.onSlot(UInt64.valueOf(10));
    asyncRunner.executeQueuedActions();

    assertThat(autoRegistrator.isFaulty(keyPair.getPublicKey())).isTrue();
    verify(validatorApiChannel, never()).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void
      processRegistrations_shouldMarkFaultyAndNotRegenerateWhenPoolRegistrationExistsAndLocalChainMissing() {
    final OwnedValidators ownedValidators =
        new OwnedValidators(Map.of(keyPair.getPublicKey(), validator));
    // No hash chain saved in store

    final RandaoCommitmentRegistrator autoRegistrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            hashChainStore,
            ownedValidators,
            spec,
            asyncRunner);

    final Bytes32 poolCommitment = dataStructureUtil.randomBytes32();
    final ValidatorRandaoCommitmentStatus status =
        new ValidatorRandaoCommitmentStatus(
            false,
            Optional.empty(),
            false,
            Optional.empty(),
            Optional.empty(),
            true,
            Optional.of(poolCommitment));

    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPair.getPublicKey()))
        .thenReturn(SafeFuture.completedFuture(status));

    autoRegistrator.onSlot(UInt64.valueOf(10));
    asyncRunner.executeQueuedActions();

    assertThat(autoRegistrator.isFaulty(keyPair.getPublicKey())).isTrue();
    // Verify no new chain was saved in store
    assertThat(hashChainStore.loadHashChain(keyPair.getPublicKey(), "")).isEmpty();
    verify(validatorApiChannel, never()).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void processRegistrations_shouldSkipWhenPendingRegistrationMatchesLocalChain() {
    final OwnedValidators ownedValidators =
        new OwnedValidators(Map.of(keyPair.getPublicKey(), validator));
    hashChainStore.storeHashChain(keyPair.getPublicKey(), hashChain, "");

    final RandaoCommitmentRegistrator autoRegistrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            hashChainStore,
            ownedValidators,
            spec,
            asyncRunner);

    final ValidatorRandaoCommitmentStatus status =
        new ValidatorRandaoCommitmentStatus(
            false,
            Optional.empty(),
            true,
            Optional.of(hashChain.getCommitment()),
            Optional.of(UInt64.valueOf(5)),
            false,
            Optional.empty());

    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPair.getPublicKey()))
        .thenReturn(SafeFuture.completedFuture(status));

    autoRegistrator.onSlot(UInt64.valueOf(10));
    asyncRunner.executeQueuedActions();

    assertThat(
            autoRegistrator.isAlreadySubmitted(keyPair.getPublicKey(), hashChain.getCommitment()))
        .isTrue();
    assertThat(autoRegistrator.isFaulty(keyPair.getPublicKey())).isFalse();
    verify(validatorApiChannel, never()).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void processRegistrations_shouldMarkFaultyWhenPendingRegistrationMismatchesLocalChain() {
    final OwnedValidators ownedValidators =
        new OwnedValidators(Map.of(keyPair.getPublicKey(), validator));
    hashChainStore.storeHashChain(keyPair.getPublicKey(), hashChain, "");

    final RandaoCommitmentRegistrator autoRegistrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            hashChainStore,
            ownedValidators,
            spec,
            asyncRunner);

    final Bytes32 differentCommitment = dataStructureUtil.randomBytes32();
    final ValidatorRandaoCommitmentStatus status =
        new ValidatorRandaoCommitmentStatus(
            false,
            Optional.empty(),
            true,
            Optional.of(differentCommitment),
            Optional.of(UInt64.valueOf(5)),
            false,
            Optional.empty());

    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPair.getPublicKey()))
        .thenReturn(SafeFuture.completedFuture(status));

    autoRegistrator.onSlot(UInt64.valueOf(10));
    asyncRunner.executeQueuedActions();

    assertThat(autoRegistrator.isFaulty(keyPair.getPublicKey())).isTrue();
    verify(validatorApiChannel, never()).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void
      processRegistrations_shouldMarkFaultyAndNotRegenerateWhenPendingRegistrationExistsAndLocalChainMissing() {
    final OwnedValidators ownedValidators =
        new OwnedValidators(Map.of(keyPair.getPublicKey(), validator));

    final RandaoCommitmentRegistrator autoRegistrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            hashChainStore,
            ownedValidators,
            spec,
            asyncRunner);

    final Bytes32 pendingCommitment = dataStructureUtil.randomBytes32();
    final ValidatorRandaoCommitmentStatus status =
        new ValidatorRandaoCommitmentStatus(
            false,
            Optional.empty(),
            true,
            Optional.of(pendingCommitment),
            Optional.of(UInt64.valueOf(5)),
            false,
            Optional.empty());

    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPair.getPublicKey()))
        .thenReturn(SafeFuture.completedFuture(status));

    autoRegistrator.onSlot(UInt64.valueOf(10));
    asyncRunner.executeQueuedActions();

    assertThat(autoRegistrator.isFaulty(keyPair.getPublicKey())).isTrue();
    assertThat(hashChainStore.loadHashChain(keyPair.getPublicKey(), "")).isEmpty();
    verify(validatorApiChannel, never()).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void processRegistrations_shouldSkipWhenActiveCommitmentExistsAndCanProduceReveal() {
    final OwnedValidators ownedValidators =
        new OwnedValidators(Map.of(keyPair.getPublicKey(), validator));
    hashChainStore.storeHashChain(keyPair.getPublicKey(), hashChain, "");

    final RandaoCommitmentRegistrator autoRegistrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            hashChainStore,
            ownedValidators,
            spec,
            asyncRunner);

    // Active commitment can be any intermediate link in the chain
    final Bytes32 activeCommitment = hashChain.getLinks().get(5);
    final ValidatorRandaoCommitmentStatus status =
        new ValidatorRandaoCommitmentStatus(
            true,
            Optional.of(activeCommitment),
            false,
            Optional.empty(),
            Optional.empty(),
            false,
            Optional.empty());

    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPair.getPublicKey()))
        .thenReturn(SafeFuture.completedFuture(status));

    autoRegistrator.onSlot(UInt64.valueOf(10));
    asyncRunner.executeQueuedActions();

    assertThat(
            autoRegistrator.isAlreadySubmitted(keyPair.getPublicKey(), hashChain.getCommitment()))
        .isTrue();
    assertThat(autoRegistrator.isFaulty(keyPair.getPublicKey())).isFalse();
    verify(validatorApiChannel, never()).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void processRegistrations_shouldMarkFaultyWhenActiveCommitmentCannotProduceReveal() {
    final OwnedValidators ownedValidators =
        new OwnedValidators(Map.of(keyPair.getPublicKey(), validator));
    hashChainStore.storeHashChain(keyPair.getPublicKey(), hashChain, "");

    final RandaoCommitmentRegistrator autoRegistrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            hashChainStore,
            ownedValidators,
            spec,
            asyncRunner);

    // Exhausted seed link c_0 cannot produce further reveals
    final Bytes32 exhaustedCommitment = hashChain.getSeed();
    final ValidatorRandaoCommitmentStatus status =
        new ValidatorRandaoCommitmentStatus(
            true,
            Optional.of(exhaustedCommitment),
            false,
            Optional.empty(),
            Optional.empty(),
            false,
            Optional.empty());

    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPair.getPublicKey()))
        .thenReturn(SafeFuture.completedFuture(status));

    autoRegistrator.onSlot(UInt64.valueOf(10));
    asyncRunner.executeQueuedActions();

    assertThat(autoRegistrator.isFaulty(keyPair.getPublicKey())).isTrue();
    verify(validatorApiChannel, never()).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void
      processRegistrations_shouldMarkFaultyAndNotRegenerateWhenActiveCommitmentExistsAndLocalChainMissing() {
    final OwnedValidators ownedValidators =
        new OwnedValidators(Map.of(keyPair.getPublicKey(), validator));

    final RandaoCommitmentRegistrator autoRegistrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            hashChainStore,
            ownedValidators,
            spec,
            asyncRunner);

    final Bytes32 activeCommitment = dataStructureUtil.randomBytes32();
    final ValidatorRandaoCommitmentStatus status =
        new ValidatorRandaoCommitmentStatus(
            true,
            Optional.of(activeCommitment),
            false,
            Optional.empty(),
            Optional.empty(),
            false,
            Optional.empty());

    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPair.getPublicKey()))
        .thenReturn(SafeFuture.completedFuture(status));

    autoRegistrator.onSlot(UInt64.valueOf(10));
    asyncRunner.executeQueuedActions();

    assertThat(autoRegistrator.isFaulty(keyPair.getPublicKey())).isTrue();
    assertThat(hashChainStore.loadHashChain(keyPair.getPublicKey(), "")).isEmpty();
    verify(validatorApiChannel, never()).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void processRegistrations_shouldGenerateStoreAndSubmitWhenNotRegistered() {
    final OwnedValidators ownedValidators =
        new OwnedValidators(Map.of(keyPair.getPublicKey(), validator));
    final Bytes32 genesisValidatorsRoot = dataStructureUtil.randomBytes32();
    final int validatorIndex = 7;

    when(genesisDataProvider.getGenesisValidatorsRoot())
        .thenReturn(SafeFuture.completedFuture(genesisValidatorsRoot));
    when(validatorIndexProvider.getValidatorIndicesByPublicKey())
        .thenReturn(SafeFuture.completedFuture(Map.of(keyPair.getPublicKey(), validatorIndex)));

    final RandaoCommitmentRegistrator autoRegistrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            hashChainStore,
            ownedValidators,
            spec,
            asyncRunner);

    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPair.getPublicKey()))
        .thenReturn(SafeFuture.completedFuture(ValidatorRandaoCommitmentStatus.NOT_REGISTERED));

    autoRegistrator.onSlot(UInt64.valueOf(10));
    asyncRunner.executeQueuedActions();
    asyncRunner.executeQueuedActions();
    asyncRunner.executeQueuedActions();

    verify(validatorApiChannel).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void processRegistrations_shouldNotRegisterWhenStatusQueryFails() {
    final OwnedValidators ownedValidators =
        new OwnedValidators(Map.of(keyPair.getPublicKey(), validator));

    final RandaoCommitmentRegistrator autoRegistrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            hashChainStore,
            ownedValidators,
            spec,
            asyncRunner);

    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPair.getPublicKey()))
        .thenReturn(SafeFuture.failedFuture(new IllegalStateException("Head state not ready")));

    autoRegistrator.onSlot(UInt64.valueOf(10));
    asyncRunner.executeQueuedActions();

    assertThat(hashChainStore.loadHashChain(keyPair.getPublicKey(), "")).isEmpty();
    assertThat(autoRegistrator.isFaulty(keyPair.getPublicKey())).isFalse();
    verify(validatorApiChannel, never()).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void processRegistrations_shouldRetryAndRegisterWhenStatusBecomesAvailableAfterFailure() {
    final OwnedValidators ownedValidators =
        new OwnedValidators(Map.of(keyPair.getPublicKey(), validator));
    final Bytes32 genesisValidatorsRoot = dataStructureUtil.randomBytes32();
    final int validatorIndex = 7;

    when(genesisDataProvider.getGenesisValidatorsRoot())
        .thenReturn(SafeFuture.completedFuture(genesisValidatorsRoot));
    when(validatorIndexProvider.getValidatorIndicesByPublicKey())
        .thenReturn(SafeFuture.completedFuture(Map.of(keyPair.getPublicKey(), validatorIndex)));

    final RandaoCommitmentRegistrator autoRegistrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            hashChainStore,
            ownedValidators,
            spec,
            asyncRunner);

    // Initial slot: BN syncing or state not ready
    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPair.getPublicKey()))
        .thenReturn(SafeFuture.failedFuture(new IllegalStateException("Head state not ready")));

    autoRegistrator.onSlot(UInt64.valueOf(10));
    asyncRunner.executeQueuedActions();

    assertThat(hashChainStore.loadHashChain(keyPair.getPublicKey(), "")).isEmpty();
    verify(validatorApiChannel, never()).sendSignedRandaoCommitmentRegistration(any());

    // Subsequent slot: state becomes available
    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPair.getPublicKey()))
        .thenReturn(SafeFuture.completedFuture(ValidatorRandaoCommitmentStatus.NOT_REGISTERED));

    autoRegistrator.onSlot(UInt64.valueOf(11));
    asyncRunner.executeQueuedActions();
    asyncRunner.executeQueuedActions();
    asyncRunner.executeQueuedActions();

    final Optional<HashChain> storedChain =
        hashChainStore.loadHashChain(keyPair.getPublicKey(), "");
    assertThat(storedChain).isPresent();
    assertThat(
            autoRegistrator.isAlreadySubmitted(
                keyPair.getPublicKey(), storedChain.get().getCommitment()))
        .isTrue();
    verify(validatorApiChannel).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void processRegistrations_shouldRespectConfiguredMaxConcurrentGenerationTasks() throws Exception {
    final int maxConcurrentTasks = 2;
    final int validatorCount = 8;
    final AtomicInteger activeGenerations = new AtomicInteger(0);
    final AtomicInteger maxConcurrentObserved = new AtomicInteger(0);

    final CountDownLatch firstTwoTasksRunning = new CountDownLatch(2);
    final CountDownLatch blockFirstTwoTasks = new CountDownLatch(1);
    final CountDownLatch allRegistrationsSubmitted = new CountDownLatch(validatorCount);

    final AsyncRunnerFactory asyncRunnerFactory =
        AsyncRunnerFactory.createDefault(
            new MetricTrackingExecutorFactory(new StubMetricsSystem()));
    final AsyncRunner concurrentAsyncRunner =
        asyncRunnerFactory.create("concurrent_test_runner", 4);

    try {
      final HashChainGenerator instrumentedGenerator =
          new HashChainGenerator() {
            @Override
            public HashChain generate(final int length) {
              final int current = activeGenerations.incrementAndGet();
              maxConcurrentObserved.accumulateAndGet(current, Math::max);
              firstTwoTasksRunning.countDown();
              try {
                if (!blockFirstTwoTasks.await(10, TimeUnit.SECONDS)) {
                  throw new RuntimeException("Timed out waiting for blockFirstTwoTasks latch");
                }
                return super.generate(10);
              } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(e);
              } finally {
                activeGenerations.decrementAndGet();
              }
            }
          };

      final Map<BLSPublicKey, Validator> validatorMap = new HashMap<>();
      final Map<BLSPublicKey, Integer> indexMap = new HashMap<>();
      final List<BLSKeyPair> keyPairs = new ArrayList<>();

      for (int i = 0; i < validatorCount; i++) {
        final BLSKeyPair kp = dataStructureUtil.randomKeyPair();
        keyPairs.add(kp);
        final Signer signer = new LocalSigner(spec, kp, concurrentAsyncRunner);
        final Validator val = new Validator(kp.getPublicKey(), signer, Optional::empty);
        validatorMap.put(kp.getPublicKey(), val);
        indexMap.put(kp.getPublicKey(), 100 + i);
        when(validatorApiChannel.getValidatorRandaoCommitmentStatus(kp.getPublicKey()))
            .thenReturn(SafeFuture.completedFuture(ValidatorRandaoCommitmentStatus.NOT_REGISTERED));
      }

      doAnswer(
              invocation -> {
                allRegistrationsSubmitted.countDown();
                return SafeFuture.COMPLETE;
              })
          .when(validatorApiChannel)
          .sendSignedRandaoCommitmentRegistration(any());

      when(genesisDataProvider.getGenesisValidatorsRoot())
          .thenReturn(SafeFuture.completedFuture(dataStructureUtil.randomBytes32()));
      when(validatorIndexProvider.getValidatorIndicesByPublicKey())
          .thenReturn(SafeFuture.completedFuture(indexMap));

      final OwnedValidators multiOwnedValidators = new OwnedValidators(validatorMap);
      final RandaoCommitmentRegistrator registrator =
          new RandaoCommitmentRegistrator(
              validatorApiChannel,
              validatorIndexProvider,
              genesisDataProvider,
              Optional.of(hashChainStore),
              Optional.of(multiOwnedValidators),
              Optional.of(spec),
              Optional.of(concurrentAsyncRunner),
              instrumentedGenerator,
              "",
              maxConcurrentTasks);

      registrator.onSlot(UInt64.valueOf(10));

      assertThat(firstTwoTasksRunning.await(10, TimeUnit.SECONDS))
          .withFailMessage("Timed out waiting for first two tasks to start concurrently")
          .isTrue();

      assertThat(maxConcurrentObserved.get()).isEqualTo(2);

      // Release the blocked first two tasks so subsequent tasks can execute
      blockFirstTwoTasks.countDown();

      assertThat(allRegistrationsSubmitted.await(10, TimeUnit.SECONDS))
          .withFailMessage("Timed out waiting for all registrations to be submitted")
          .isTrue();

      assertThat(maxConcurrentObserved.get()).isEqualTo(maxConcurrentTasks);
      verify(validatorApiChannel, times(validatorCount))
          .sendSignedRandaoCommitmentRegistration(any());

      for (final BLSKeyPair kp : keyPairs) {
        assertThat(hashChainStore.loadHashChain(kp.getPublicKey(), "")).isPresent();
      }
    } finally {
      asyncRunnerFactory.shutdown();
    }
  }

  @Test
  void processRegistrations_shouldStoreAndRegisterWithConfiguredPassword() {
    final String password = "custom_secret_password";
    final HashChainPasswordProvider passwordProvider =
        pk -> pk.equals(keyPair.getPublicKey()) ? Optional.of(password) : Optional.empty();
    final OwnedValidators ownedValidators =
        new OwnedValidators(Map.of(keyPair.getPublicKey(), validator));
    final Bytes32 genesisValidatorsRoot = dataStructureUtil.randomBytes32();
    final int validatorIndex = 7;

    when(genesisDataProvider.getGenesisValidatorsRoot())
        .thenReturn(SafeFuture.completedFuture(genesisValidatorsRoot));
    when(validatorIndexProvider.getValidatorIndicesByPublicKey())
        .thenReturn(SafeFuture.completedFuture(Map.of(keyPair.getPublicKey(), validatorIndex)));

    final RandaoCommitmentRegistrator autoRegistrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            Optional.of(hashChainStore),
            Optional.of(ownedValidators),
            Optional.of(spec),
            Optional.of(asyncRunner),
            new HashChainGenerator(),
            passwordProvider);

    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPair.getPublicKey()))
        .thenReturn(SafeFuture.completedFuture(ValidatorRandaoCommitmentStatus.NOT_REGISTERED));

    autoRegistrator.onSlot(UInt64.valueOf(10));
    while (asyncRunner.hasDelayedActions()) {
      asyncRunner.executeQueuedActions();
    }

    assertThat(hashChainStore.loadHashChain(keyPair.getPublicKey(), password)).isPresent();
    assertThatThrownBy(() -> hashChainStore.loadHashChain(keyPair.getPublicKey(), "wrong_password"))
        .isInstanceOf(Exception.class);
    assertThatThrownBy(() -> hashChainStore.loadHashChain(keyPair.getPublicKey(), ""))
        .isInstanceOf(Exception.class);

    verify(validatorApiChannel).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void processRegistrations_shouldSkipWhenNoPasswordAvailableForUnregisteredValidator() {
    final HashChainPasswordProvider passwordProvider = HashChainPasswordProvider.NOOP;
    final OwnedValidators ownedValidators =
        new OwnedValidators(Map.of(keyPair.getPublicKey(), validator));

    final RandaoCommitmentRegistrator autoRegistrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            Optional.of(hashChainStore),
            Optional.of(ownedValidators),
            Optional.of(spec),
            Optional.of(asyncRunner),
            new HashChainGenerator(),
            passwordProvider);

    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPair.getPublicKey()))
        .thenReturn(SafeFuture.completedFuture(ValidatorRandaoCommitmentStatus.NOT_REGISTERED));

    autoRegistrator.onSlot(UInt64.valueOf(10));
    while (asyncRunner.hasDelayedActions()) {
      asyncRunner.executeQueuedActions();
    }

    assertThat(hashChainStore.loadHashChain(keyPair.getPublicKey(), "")).isEmpty();
    verify(validatorApiChannel, never()).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void processRegistrations_shouldFailSafelyWhenActiveCommitmentExistsButCannotDecryptWithPassword()
      throws Exception {
    final HashChain generated = new HashChainGenerator().generate(10);
    final String correctPassword = "correct_password";
    hashChainStore.storeHashChain(keyPair.getPublicKey(), generated, correctPassword);

    final HashChainPasswordProvider wrongPasswordProvider = pk -> Optional.of("wrong_password");
    final OwnedValidators ownedValidators =
        new OwnedValidators(Map.of(keyPair.getPublicKey(), validator));

    final RandaoCommitmentRegistrator autoRegistrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            Optional.of(hashChainStore),
            Optional.of(ownedValidators),
            Optional.of(spec),
            Optional.of(asyncRunner),
            new HashChainGenerator(),
            wrongPasswordProvider);

    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPair.getPublicKey()))
        .thenReturn(
            SafeFuture.completedFuture(
                new ValidatorRandaoCommitmentStatus(
                    true,
                    Optional.of(generated.getCommitment()),
                    false,
                    Optional.empty(),
                    Optional.empty(),
                    false,
                    Optional.empty())));

    autoRegistrator.onSlot(UInt64.valueOf(10));
    while (asyncRunner.hasDelayedActions()) {
      asyncRunner.executeQueuedActions();
    }

    assertThat(autoRegistrator.isFaulty(keyPair.getPublicKey())).isTrue();
    // The original file remains untouched and decryptable with correct password
    assertThat(hashChainStore.loadHashChain(keyPair.getPublicKey(), correctPassword)).isPresent();
    assertThat(
            hashChainStore
                .loadHashChain(keyPair.getPublicKey(), correctPassword)
                .get()
                .getCommitment())
        .isEqualTo(generated.getCommitment());
    verify(validatorApiChannel, never()).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void processRegistrations_whenUnregisteredAndFileExistsWithWrongPassword_shouldFailSafely()
      throws Exception {
    final HashChain generated = new HashChainGenerator().generate(10);
    final String correctPassword = "correct_password";
    hashChainStore.storeHashChain(keyPair.getPublicKey(), generated, correctPassword);

    final HashChainPasswordProvider wrongPasswordProvider = pk -> Optional.of("wrong_password");
    final OwnedValidators ownedValidators =
        new OwnedValidators(Map.of(keyPair.getPublicKey(), validator));

    final RandaoCommitmentRegistrator autoRegistrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            Optional.of(hashChainStore),
            Optional.of(ownedValidators),
            Optional.of(spec),
            Optional.of(asyncRunner),
            new HashChainGenerator(),
            wrongPasswordProvider);

    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPair.getPublicKey()))
        .thenReturn(SafeFuture.completedFuture(ValidatorRandaoCommitmentStatus.NOT_REGISTERED));

    autoRegistrator.onSlot(UInt64.valueOf(10));
    while (asyncRunner.hasDelayedActions()) {
      asyncRunner.executeQueuedActions();
    }

    assertThat(autoRegistrator.isFaulty(keyPair.getPublicKey())).isTrue();
    // The original file remains untouched and decryptable with correct password
    assertThat(hashChainStore.loadHashChain(keyPair.getPublicKey(), correctPassword)).isPresent();
    assertThat(
            hashChainStore
                .loadHashChain(keyPair.getPublicKey(), correctPassword)
                .get()
                .getCommitment())
        .isEqualTo(generated.getCommitment());
    verify(validatorApiChannel, never()).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void processRegistrations_whenUnregisteredAndFileExistsCorrupted_shouldFailSafely()
      throws Exception {
    final Path filePath = hashChainStore.getPathForPublicKey(keyPair.getPublicKey());
    Files.createDirectories(filePath.getParent());
    Files.writeString(filePath, "{ invalid corrupted json }", UTF_8);

    final HashChainPasswordProvider passwordProvider = pk -> Optional.of("test_password");
    final OwnedValidators ownedValidators =
        new OwnedValidators(Map.of(keyPair.getPublicKey(), validator));

    final RandaoCommitmentRegistrator autoRegistrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            Optional.of(hashChainStore),
            Optional.of(ownedValidators),
            Optional.of(spec),
            Optional.of(asyncRunner),
            new HashChainGenerator(),
            passwordProvider);

    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPair.getPublicKey()))
        .thenReturn(SafeFuture.completedFuture(ValidatorRandaoCommitmentStatus.NOT_REGISTERED));

    autoRegistrator.onSlot(UInt64.valueOf(10));
    while (asyncRunner.hasDelayedActions()) {
      asyncRunner.executeQueuedActions();
    }

    assertThat(autoRegistrator.isFaulty(keyPair.getPublicKey())).isTrue();
    // The corrupted file was not overwritten with a newly generated valid file
    final String content = Files.readString(filePath, UTF_8);
    assertThat(content).isEqualTo("{ invalid corrupted json }");
    verify(validatorApiChannel, never()).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void processRegistrations_whenUnregisteredAndFileExistsValid_shouldReuseExistingChain()
      throws Exception {
    final HashChain existingChain = new HashChainGenerator().generate(10);
    final String password = "test_password";
    hashChainStore.storeHashChain(keyPair.getPublicKey(), existingChain, password);

    final HashChainPasswordProvider passwordProvider = pk -> Optional.of(password);
    final OwnedValidators ownedValidators =
        new OwnedValidators(Map.of(keyPair.getPublicKey(), validator));
    final Bytes32 genesisValidatorsRoot = dataStructureUtil.randomBytes32();
    final int validatorIndex = 5;

    when(genesisDataProvider.getGenesisValidatorsRoot())
        .thenReturn(SafeFuture.completedFuture(genesisValidatorsRoot));
    when(validatorIndexProvider.getValidatorIndicesByPublicKey())
        .thenReturn(SafeFuture.completedFuture(Map.of(keyPair.getPublicKey(), validatorIndex)));

    final RandaoCommitmentRegistrator autoRegistrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            Optional.of(hashChainStore),
            Optional.of(ownedValidators),
            Optional.of(spec),
            Optional.of(asyncRunner),
            new HashChainGenerator(),
            passwordProvider);

    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPair.getPublicKey()))
        .thenReturn(SafeFuture.completedFuture(ValidatorRandaoCommitmentStatus.NOT_REGISTERED));

    autoRegistrator.onSlot(UInt64.valueOf(10));
    while (asyncRunner.hasDelayedActions()) {
      asyncRunner.executeQueuedActions();
    }

    assertThat(autoRegistrator.isFaulty(keyPair.getPublicKey())).isFalse();
    // Existing file is intact
    assertThat(hashChainStore.loadHashChain(keyPair.getPublicKey(), password)).isPresent();
    assertThat(hashChainStore.loadHashChain(keyPair.getPublicKey(), password).get().getCommitment())
        .isEqualTo(existingChain.getCommitment());

    final ArgumentCaptor<SignedRandaoCommitmentRegistration> captor =
        ArgumentCaptor.forClass(SignedRandaoCommitmentRegistration.class);
    verify(validatorApiChannel).sendSignedRandaoCommitmentRegistration(captor.capture());
    assertThat(captor.getValue().getMessage().getCommitment())
        .isEqualTo(existingChain.getCommitment());
  }
}
