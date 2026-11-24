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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSPublicKey;
import tech.pegasys.teku.infrastructure.async.SafeFuture;
import tech.pegasys.teku.infrastructure.async.StubAsyncRunner;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.Spec;
import tech.pegasys.teku.spec.TestSpecFactory;
import tech.pegasys.teku.spec.datastructures.interop.MockStartValidatorKeyPairFactory;
import tech.pegasys.teku.spec.datastructures.operations.SignedRandaoCommitmentRegistration;
import tech.pegasys.teku.spec.signatures.LocalSigner;
import tech.pegasys.teku.spec.signatures.Signer;
import tech.pegasys.teku.spec.util.DataStructureUtil;
import tech.pegasys.teku.validator.api.ValidatorApiChannel;
import tech.pegasys.teku.validator.api.ValidatorRandaoCommitmentStatus;
import tech.pegasys.teku.validator.beaconnode.GenesisDataProvider;
import tech.pegasys.teku.validator.client.hashchain.HashChain;
import tech.pegasys.teku.validator.client.hashchain.HashChainGenerator;
import tech.pegasys.teku.validator.client.hashchain.HashChainPasswordProvider;
import tech.pegasys.teku.validator.client.hashchain.HashChainStore;
import tech.pegasys.teku.validator.client.hashchain.RandaoCommitmentRegistrator;
import tech.pegasys.teku.validator.client.loader.OwnedValidators;

class RandaoCommitmentRegistrationLifecycleTest {

  private final Spec spec = TestSpecFactory.createMinimalEip8321();
  private final DataStructureUtil dataStructureUtil = new DataStructureUtil(spec);
  private final StubAsyncRunner asyncRunner = new StubAsyncRunner();

  private final ValidatorApiChannel validatorApiChannel = mock(ValidatorApiChannel.class);
  private final ValidatorIndexProvider validatorIndexProvider = mock(ValidatorIndexProvider.class);
  private final GenesisDataProvider genesisDataProvider = mock(GenesisDataProvider.class);

  private final Bytes32 genesisValidatorsRoot = dataStructureUtil.randomBytes32();
  private List<BLSKeyPair> keyPairs;
  private OwnedValidators ownedValidators;
  private HashChainStore hashChainStore;

  @BeforeEach
  void setUp(@TempDir final Path tempDir) {
    keyPairs = new MockStartValidatorKeyPairFactory().generateKeyPairs(256, 260);
    ownedValidators = new OwnedValidators();
    final Map<BLSPublicKey, Integer> indexMap = new HashMap<>();

    for (int i = 0; i < keyPairs.size(); i++) {
      final BLSKeyPair kp = keyPairs.get(i);
      final int valIndex = 256 + i;
      final Signer signer = new LocalSigner(spec, kp, asyncRunner);
      final Validator val = new Validator(kp.getPublicKey(), signer, Optional::empty);
      ownedValidators.addValidator(val);
      indexMap.put(kp.getPublicKey(), valIndex);
    }

    hashChainStore = new HashChainStore(tempDir, 1000);

    when(genesisDataProvider.getGenesisValidatorsRoot())
        .thenReturn(SafeFuture.completedFuture(genesisValidatorsRoot));
    when(validatorIndexProvider.getValidatorIndicesByPublicKey())
        .thenReturn(SafeFuture.completedFuture(indexMap));
    when(validatorApiChannel.sendSignedRandaoCommitmentRegistration(any()))
        .thenReturn(SafeFuture.COMPLETE);
  }

  @Test
  void shouldAutomaticallyRegisterAllOwnedValidatorsOnStartup() {
    final RandaoCommitmentRegistrator registrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            hashChainStore,
            ownedValidators,
            spec,
            asyncRunner);

    // Initial state: not registered anywhere
    for (final BLSKeyPair kp : keyPairs) {
      when(validatorApiChannel.getValidatorRandaoCommitmentStatus(kp.getPublicKey()))
          .thenReturn(SafeFuture.completedFuture(ValidatorRandaoCommitmentStatus.NOT_REGISTERED));
    }

    // Trigger onSlot event
    registrator.onSlot(UInt64.valueOf(1));
    while (asyncRunner.hasDelayedActions()) {
      asyncRunner.executeQueuedActions();
    }

    // Verify registrations were sent for all 4 validators
    final ArgumentCaptor<SignedRandaoCommitmentRegistration> captor =
        ArgumentCaptor.forClass(SignedRandaoCommitmentRegistration.class);
    verify(validatorApiChannel, times(4)).sendSignedRandaoCommitmentRegistration(captor.capture());

    final List<SignedRandaoCommitmentRegistration> submitted = captor.getAllValues();
    assertThat(submitted).hasSize(4);

    for (int i = 0; i < keyPairs.size(); i++) {
      final BLSPublicKey pubKey = keyPairs.get(i).getPublicKey();
      final UInt64 expectedIndex = UInt64.valueOf(256 + i);

      final Optional<HashChain> chain = hashChainStore.loadHashChain(pubKey, "");
      assertThat(chain).isPresent();

      final Optional<SignedRandaoCommitmentRegistration> reg =
          submitted.stream()
              .filter(r -> r.getMessage().getValidatorIndex().equals(expectedIndex))
              .findFirst();
      assertThat(reg).isPresent();
      assertThat(reg.get().getMessage().getCommitment()).isEqualTo(chain.get().getCommitment());
      assertThat(registrator.isAlreadySubmitted(pubKey, chain.get().getCommitment())).isTrue();
    }
  }

  @Test
  void shouldNotResubmitOnRestartWhenCommitmentsArePendingOrActive() {
    // 1. Simulate initial registration run
    final RandaoCommitmentRegistrator registrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            hashChainStore,
            ownedValidators,
            spec,
            asyncRunner);

    for (final BLSKeyPair kp : keyPairs) {
      when(validatorApiChannel.getValidatorRandaoCommitmentStatus(kp.getPublicKey()))
          .thenReturn(SafeFuture.completedFuture(ValidatorRandaoCommitmentStatus.NOT_REGISTERED));
    }

    registrator.onSlot(UInt64.valueOf(1));
    while (asyncRunner.hasDelayedActions()) {
      asyncRunner.executeQueuedActions();
    }

    verify(validatorApiChannel, times(4)).sendSignedRandaoCommitmentRegistration(any());

    // 2. Simulate node restart: create a new registrator instance sharing the existing disk store
    final RandaoCommitmentRegistrator restartedRegistrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            hashChainStore,
            ownedValidators,
            spec,
            asyncRunner);

    // Simulate canonical state: validator 256 is active (revealed 1 link), 257 is pending, 258 is
    // in pool, 259 is not yet included
    final HashChain chain0 =
        hashChainStore.loadHashChain(keyPairs.get(0).getPublicKey(), "").orElseThrow();
    final HashChain chain1 =
        hashChainStore.loadHashChain(keyPairs.get(1).getPublicKey(), "").orElseThrow();
    final HashChain chain2 =
        hashChainStore.loadHashChain(keyPairs.get(2).getPublicKey(), "").orElseThrow();

    // 256 is active at link c_{n-1}
    final Bytes32 activeCommitment = chain0.getLinks().get(chain0.getLength() - 1);
    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPairs.get(0).getPublicKey()))
        .thenReturn(
            SafeFuture.completedFuture(
                new ValidatorRandaoCommitmentStatus(
                    true,
                    Optional.of(activeCommitment),
                    false,
                    Optional.empty(),
                    Optional.empty(),
                    false,
                    Optional.empty())));

    // 257 is pending
    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPairs.get(1).getPublicKey()))
        .thenReturn(
            SafeFuture.completedFuture(
                new ValidatorRandaoCommitmentStatus(
                    false,
                    Optional.empty(),
                    true,
                    Optional.of(chain1.getCommitment()),
                    Optional.of(UInt64.valueOf(4)),
                    false,
                    Optional.empty())));

    // 258 is in pool
    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPairs.get(2).getPublicKey()))
        .thenReturn(
            SafeFuture.completedFuture(
                new ValidatorRandaoCommitmentStatus(
                    false,
                    Optional.empty(),
                    false,
                    Optional.empty(),
                    Optional.empty(),
                    true,
                    Optional.of(chain2.getCommitment()))));

    // 259 is already submitted locally and status now reports pool
    final HashChain chain3 =
        hashChainStore.loadHashChain(keyPairs.get(3).getPublicKey(), "").orElseThrow();
    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(keyPairs.get(3).getPublicKey()))
        .thenReturn(
            SafeFuture.completedFuture(
                new ValidatorRandaoCommitmentStatus(
                    false,
                    Optional.empty(),
                    false,
                    Optional.empty(),
                    Optional.empty(),
                    true,
                    Optional.of(chain3.getCommitment()))));

    // Trigger onSlot on the restarted node
    restartedRegistrator.onSlot(UInt64.valueOf(10));
    asyncRunner.executeQueuedActions();
    asyncRunner.executeQueuedActions();

    // No additional registrations should be submitted
    verify(validatorApiChannel, times(4)).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void shouldHandleReorgWhereRegistrationReturnsToPool() {
    final BLSKeyPair kp = keyPairs.get(0);
    final Signer signer = new LocalSigner(spec, kp, asyncRunner);
    final Validator val = new Validator(kp.getPublicKey(), signer, Optional::empty);
    final OwnedValidators singleOwnedValidators =
        new OwnedValidators(Map.of(kp.getPublicKey(), val));

    final RandaoCommitmentRegistrator registrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            hashChainStore,
            singleOwnedValidators,
            spec,
            asyncRunner);

    // Generate chain in store
    final HashChain chain = new HashChainGenerator().generate(100);
    hashChainStore.storeHashChain(kp.getPublicKey(), chain, "");

    // After reorg, registration is returned to pool
    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(kp.getPublicKey()))
        .thenReturn(
            SafeFuture.completedFuture(
                new ValidatorRandaoCommitmentStatus(
                    false,
                    Optional.empty(),
                    false,
                    Optional.empty(),
                    Optional.empty(),
                    true,
                    Optional.of(chain.getCommitment()))));

    registrator.onSlot(UInt64.valueOf(20));
    asyncRunner.executeQueuedActions();
    asyncRunner.executeQueuedActions();

    // Should detect in pool and not re-submit
    verify(validatorApiChannel, never()).sendSignedRandaoCommitmentRegistration(any());
    assertThat(registrator.isFaulty(kp.getPublicKey())).isFalse();
    assertThat(registrator.isAlreadySubmitted(kp.getPublicKey(), chain.getCommitment())).isTrue();
  }

  @Test
  void shouldNotRegenerateOrOverwriteWhenCorruptedHashChainFileExists() throws Exception {
    final BLSKeyPair kp = keyPairs.get(0);
    final Signer signer = new LocalSigner(spec, kp, asyncRunner);
    final Validator val = new Validator(kp.getPublicKey(), signer, Optional::empty);
    final OwnedValidators singleOwnedValidators =
        new OwnedValidators(Map.of(kp.getPublicKey(), val));

    final Path filePath = hashChainStore.getPathForPublicKey(kp.getPublicKey());
    Files.createDirectories(filePath.getParent());
    Files.writeString(filePath, "{ invalid corrupted json }", UTF_8);

    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(kp.getPublicKey()))
        .thenReturn(SafeFuture.completedFuture(ValidatorRandaoCommitmentStatus.NOT_REGISTERED));

    final RandaoCommitmentRegistrator registrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            hashChainStore,
            singleOwnedValidators,
            spec,
            asyncRunner);

    registrator.onSlot(UInt64.valueOf(10));
    asyncRunner.executeQueuedActions();
    asyncRunner.executeQueuedActions();

    assertThat(registrator.isFaulty(kp.getPublicKey())).isTrue();
    final String content = Files.readString(filePath, UTF_8);
    assertThat(content).isEqualTo("{ invalid corrupted json }");
    verify(validatorApiChannel, never()).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void shouldNotRegenerateOrOverwriteWhenHashChainFileHasWrongPassword() throws Exception {
    final BLSKeyPair kp = keyPairs.get(0);
    final Signer signer = new LocalSigner(spec, kp, asyncRunner);
    final Validator val = new Validator(kp.getPublicKey(), signer, Optional::empty);
    final OwnedValidators singleOwnedValidators =
        new OwnedValidators(Map.of(kp.getPublicKey(), val));

    final HashChain existingChain = new HashChainGenerator().generate(10);
    final String correctPassword = "correct_password";
    hashChainStore.storeHashChain(kp.getPublicKey(), existingChain, correctPassword);

    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(kp.getPublicKey()))
        .thenReturn(SafeFuture.completedFuture(ValidatorRandaoCommitmentStatus.NOT_REGISTERED));

    final HashChainPasswordProvider wrongPasswordProvider = pubKey -> Optional.of("wrong_password");

    final RandaoCommitmentRegistrator registrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            Optional.of(hashChainStore),
            Optional.of(singleOwnedValidators),
            Optional.of(spec),
            Optional.of(asyncRunner),
            new HashChainGenerator(),
            wrongPasswordProvider);

    registrator.onSlot(UInt64.valueOf(10));
    asyncRunner.executeQueuedActions();
    asyncRunner.executeQueuedActions();

    assertThat(registrator.isFaulty(kp.getPublicKey())).isTrue();
    assertThat(hashChainStore.loadHashChain(kp.getPublicKey(), correctPassword)).isPresent();
    assertThat(
            hashChainStore.loadHashChain(kp.getPublicKey(), correctPassword).get().getCommitment())
        .isEqualTo(existingChain.getCommitment());
    verify(validatorApiChannel, never()).sendSignedRandaoCommitmentRegistration(any());
  }

  @Test
  void shouldReuseExistingValidHashChainFileOnStartup() throws Exception {
    final BLSKeyPair kp = keyPairs.get(0);
    final Signer signer = new LocalSigner(spec, kp, asyncRunner);
    final Validator val = new Validator(kp.getPublicKey(), signer, Optional::empty);
    final OwnedValidators singleOwnedValidators =
        new OwnedValidators(Map.of(kp.getPublicKey(), val));

    final HashChain existingChain = new HashChainGenerator().generate(10);
    hashChainStore.storeHashChain(kp.getPublicKey(), existingChain, "");

    when(validatorApiChannel.getValidatorRandaoCommitmentStatus(kp.getPublicKey()))
        .thenReturn(SafeFuture.completedFuture(ValidatorRandaoCommitmentStatus.NOT_REGISTERED));

    final RandaoCommitmentRegistrator registrator =
        new RandaoCommitmentRegistrator(
            validatorApiChannel,
            validatorIndexProvider,
            genesisDataProvider,
            hashChainStore,
            singleOwnedValidators,
            spec,
            asyncRunner);

    registrator.onSlot(UInt64.valueOf(10));
    asyncRunner.executeQueuedActions();
    asyncRunner.executeQueuedActions();

    assertThat(registrator.isFaulty(kp.getPublicKey())).isFalse();
    final ArgumentCaptor<SignedRandaoCommitmentRegistration> captor =
        ArgumentCaptor.forClass(SignedRandaoCommitmentRegistration.class);
    verify(validatorApiChannel).sendSignedRandaoCommitmentRegistration(captor.capture());
    assertThat(captor.getValue().getMessage().getCommitment())
        .isEqualTo(existingChain.getCommitment());
    assertThat(hashChainStore.loadHashChain(kp.getPublicKey(), "").get().getCommitment())
        .isEqualTo(existingChain.getCommitment());
  }
}
