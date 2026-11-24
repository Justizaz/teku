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

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.annotations.VisibleForTesting;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes32;
import tech.pegasys.teku.api.response.ValidatorStatus;
import tech.pegasys.teku.bls.BLSPublicKey;
import tech.pegasys.teku.infrastructure.async.AsyncRunner;
import tech.pegasys.teku.infrastructure.async.SafeFuture;
import tech.pegasys.teku.infrastructure.async.ThrottlingTaskQueue;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.Spec;
import tech.pegasys.teku.spec.SpecMilestone;
import tech.pegasys.teku.spec.datastructures.operations.RandaoCommitmentRegistration;
import tech.pegasys.teku.spec.datastructures.operations.SignedRandaoCommitmentRegistration;
import tech.pegasys.teku.validator.api.ValidatorApiChannel;
import tech.pegasys.teku.validator.api.ValidatorRandaoCommitmentStatus;
import tech.pegasys.teku.validator.api.ValidatorTimingChannel;
import tech.pegasys.teku.validator.beaconnode.GenesisDataProvider;
import tech.pegasys.teku.validator.client.Validator;
import tech.pegasys.teku.validator.client.ValidatorIndexProvider;
import tech.pegasys.teku.validator.client.loader.OwnedValidators;

public class RandaoCommitmentRegistrator implements ValidatorTimingChannel {
  private static final Logger LOG = LogManager.getLogger();
  public static final int DEFAULT_MAX_CONCURRENT_HASH_CHAIN_GENERATION_TASKS = 8;

  private final ValidatorApiChannel validatorApiChannel;
  private final ValidatorIndexProvider validatorIndexProvider;
  private final GenesisDataProvider genesisDataProvider;
  private final Optional<HashChainStore> hashChainStore;
  private final Optional<OwnedValidators> ownedValidators;
  private final Optional<Spec> spec;
  private final Optional<AsyncRunner> asyncRunner;
  private final HashChainGenerator hashChainGenerator;
  private final HashChainPasswordProvider hashChainPasswordProvider;
  private final ThrottlingTaskQueue generationTaskQueue;

  private final Map<BLSPublicKey, Bytes32> submittedRegistrations = new ConcurrentHashMap<>();
  private final Set<BLSPublicKey> inFlightRegistrations = ConcurrentHashMap.newKeySet();
  private final Set<BLSPublicKey> faultyValidators = ConcurrentHashMap.newKeySet();
  private final AtomicBoolean registrationInProgress = new AtomicBoolean(false);

  private volatile UInt64 currentSlot;

  public RandaoCommitmentRegistrator(
      final ValidatorApiChannel validatorApiChannel,
      final ValidatorIndexProvider validatorIndexProvider,
      final GenesisDataProvider genesisDataProvider) {
    this(
        validatorApiChannel,
        validatorIndexProvider,
        genesisDataProvider,
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        new HashChainGenerator(),
        pk -> Optional.of(""));
  }

  public RandaoCommitmentRegistrator(
      final ValidatorApiChannel validatorApiChannel,
      final ValidatorIndexProvider validatorIndexProvider,
      final GenesisDataProvider genesisDataProvider,
      final HashChainStore hashChainStore) {
    this(
        validatorApiChannel,
        validatorIndexProvider,
        genesisDataProvider,
        Optional.ofNullable(hashChainStore),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        new HashChainGenerator(),
        pk -> Optional.of(""));
  }

  public RandaoCommitmentRegistrator(
      final ValidatorApiChannel validatorApiChannel,
      final ValidatorIndexProvider validatorIndexProvider,
      final GenesisDataProvider genesisDataProvider,
      final HashChainStore hashChainStore,
      final OwnedValidators ownedValidators,
      final Spec spec,
      final AsyncRunner asyncRunner) {
    this(
        validatorApiChannel,
        validatorIndexProvider,
        genesisDataProvider,
        Optional.ofNullable(hashChainStore),
        Optional.ofNullable(ownedValidators),
        Optional.ofNullable(spec),
        Optional.ofNullable(asyncRunner),
        new HashChainGenerator(),
        pk -> Optional.of(""));
  }

  public RandaoCommitmentRegistrator(
      final ValidatorApiChannel validatorApiChannel,
      final ValidatorIndexProvider validatorIndexProvider,
      final GenesisDataProvider genesisDataProvider,
      final Optional<HashChainStore> hashChainStore,
      final Optional<OwnedValidators> ownedValidators,
      final Optional<Spec> spec,
      final Optional<AsyncRunner> asyncRunner,
      final HashChainGenerator hashChainGenerator,
      final String password) {
    this(
        validatorApiChannel,
        validatorIndexProvider,
        genesisDataProvider,
        hashChainStore,
        ownedValidators,
        spec,
        asyncRunner,
        hashChainGenerator,
        pk -> Optional.ofNullable(password),
        DEFAULT_MAX_CONCURRENT_HASH_CHAIN_GENERATION_TASKS);
  }

  public RandaoCommitmentRegistrator(
      final ValidatorApiChannel validatorApiChannel,
      final ValidatorIndexProvider validatorIndexProvider,
      final GenesisDataProvider genesisDataProvider,
      final Optional<HashChainStore> hashChainStore,
      final Optional<OwnedValidators> ownedValidators,
      final Optional<Spec> spec,
      final Optional<AsyncRunner> asyncRunner,
      final HashChainGenerator hashChainGenerator,
      final HashChainPasswordProvider hashChainPasswordProvider) {
    this(
        validatorApiChannel,
        validatorIndexProvider,
        genesisDataProvider,
        hashChainStore,
        ownedValidators,
        spec,
        asyncRunner,
        hashChainGenerator,
        hashChainPasswordProvider,
        DEFAULT_MAX_CONCURRENT_HASH_CHAIN_GENERATION_TASKS);
  }

  public RandaoCommitmentRegistrator(
      final ValidatorApiChannel validatorApiChannel,
      final ValidatorIndexProvider validatorIndexProvider,
      final GenesisDataProvider genesisDataProvider,
      final Optional<HashChainStore> hashChainStore,
      final Optional<OwnedValidators> ownedValidators,
      final Optional<Spec> spec,
      final Optional<AsyncRunner> asyncRunner,
      final HashChainGenerator hashChainGenerator,
      final String password,
      final int maxConcurrentGenerationTasks) {
    this(
        validatorApiChannel,
        validatorIndexProvider,
        genesisDataProvider,
        hashChainStore,
        ownedValidators,
        spec,
        asyncRunner,
        hashChainGenerator,
        pk -> Optional.ofNullable(password),
        maxConcurrentGenerationTasks);
  }

  public RandaoCommitmentRegistrator(
      final ValidatorApiChannel validatorApiChannel,
      final ValidatorIndexProvider validatorIndexProvider,
      final GenesisDataProvider genesisDataProvider,
      final Optional<HashChainStore> hashChainStore,
      final Optional<OwnedValidators> ownedValidators,
      final Optional<Spec> spec,
      final Optional<AsyncRunner> asyncRunner,
      final HashChainGenerator hashChainGenerator,
      final HashChainPasswordProvider hashChainPasswordProvider,
      final int maxConcurrentGenerationTasks) {
    this.validatorApiChannel =
        checkNotNull(validatorApiChannel, "validatorApiChannel cannot be null");
    this.validatorIndexProvider =
        checkNotNull(validatorIndexProvider, "validatorIndexProvider cannot be null");
    this.genesisDataProvider =
        checkNotNull(genesisDataProvider, "genesisDataProvider cannot be null");
    this.hashChainStore = checkNotNull(hashChainStore, "hashChainStore cannot be null");
    this.ownedValidators = checkNotNull(ownedValidators, "ownedValidators cannot be null");
    this.spec = checkNotNull(spec, "spec cannot be null");
    this.asyncRunner = checkNotNull(asyncRunner, "asyncRunner cannot be null");
    this.hashChainGenerator = checkNotNull(hashChainGenerator, "hashChainGenerator cannot be null");
    this.hashChainPasswordProvider =
        checkNotNull(hashChainPasswordProvider, "hashChainPasswordProvider cannot be null");
    this.generationTaskQueue =
        ThrottlingTaskQueue.create(
            maxConcurrentGenerationTasks, ThrottlingTaskQueue.DEFAULT_MAXIMUM_QUEUE_SIZE);
  }

  @Override
  public void onSlot(final UInt64 slot) {
    this.currentSlot = slot;
    if (spec.isEmpty()
        || !spec.get().atSlot(slot).getMilestone().isGreaterThanOrEqualTo(SpecMilestone.EIP8321)) {
      return;
    }
    if (asyncRunner.isPresent()) {
      asyncRunner.get().runAsync(this::processRegistrations).finishError(LOG);
    } else {
      processRegistrations().finishError(LOG);
    }
  }

  @Override
  public void onUpdatedValidatorStatuses(
      final Map<BLSPublicKey, ValidatorStatus> newValidatorStatuses,
      final boolean possibleMissingEvents) {
    if (currentSlot == null
        || spec.isEmpty()
        || !spec.get()
            .atSlot(currentSlot)
            .getMilestone()
            .isGreaterThanOrEqualTo(SpecMilestone.EIP8321)) {
      return;
    }
    if (asyncRunner.isPresent()) {
      asyncRunner.get().runAsync(this::processRegistrations).finishError(LOG);
    } else {
      processRegistrations().finishError(LOG);
    }
  }

  public SafeFuture<Void> processRegistrations() {
    if (ownedValidators.isEmpty() || hashChainStore.isEmpty()) {
      return SafeFuture.COMPLETE;
    }
    if (!registrationInProgress.compareAndSet(false, true)) {
      return SafeFuture.COMPLETE;
    }

    final List<Validator> validators = ownedValidators.get().getValidators();
    if (validators.isEmpty()) {
      registrationInProgress.set(false);
      return SafeFuture.COMPLETE;
    }

    final List<SafeFuture<Void>> futures =
        validators.stream()
            .map(
                validator ->
                    validatorApiChannel
                        .getValidatorRandaoCommitmentStatus(validator.getPublicKey())
                        .thenCompose(status -> processValidatorStatus(validator, status))
                        .exceptionally(
                            error -> {
                              LOG.debug(
                                  "Failed to check/process RANDAO commitment status for validator {}: {}",
                                  validator.getPublicKey(),
                                  error.getMessage());
                              return null;
                            }))
            .toList();

    return SafeFuture.allOf(futures.toArray(SafeFuture[]::new))
        .alwaysRun(() -> registrationInProgress.set(false));
  }

  public SafeFuture<Void> processValidatorStatus(
      final Validator validator, final ValidatorRandaoCommitmentStatus status) {
    final BLSPublicKey publicKey = validator.getPublicKey();
    if (faultyValidators.contains(publicKey)) {
      return SafeFuture.COMPLETE;
    }

    final HashChainStore store = hashChainStore.orElse(null);
    if (store == null) {
      return SafeFuture.COMPLETE;
    }

    // 1. If in operation pool
    if (status.hasPoolRegistration()) {
      final Bytes32 poolCommitment = status.poolCommitment().orElseThrow();
      final Optional<HashChain> maybeChain = loadLocalChain(store, publicKey);
      if (maybeChain.isEmpty()) {
        LOG.error(
            "Validator {} has in-flight registration in operation pool with commitment {} but local hash chain file is missing or corrupted. Regeneration aborted for safety.",
            publicKey,
            poolCommitment);
        faultyValidators.add(publicKey);
        return SafeFuture.COMPLETE;
      }
      final HashChain chain = maybeChain.get();
      if (!chain.getCommitment().equals(poolCommitment)) {
        LOG.error(
            "Validator {} has in-flight registration in operation pool with commitment {} but local hash chain tip is {}. Mismatch detected; registration aborted for safety.",
            publicKey,
            poolCommitment,
            chain.getCommitment());
        faultyValidators.add(publicKey);
        return SafeFuture.COMPLETE;
      }
      markSubmitted(publicKey, chain.getCommitment());
      return SafeFuture.COMPLETE;
    }

    // 2. If pending on chain
    if (status.hasPendingRegistration()) {
      final Bytes32 pendingCommitment = status.pendingCommitment().orElseThrow();
      final Optional<HashChain> maybeChain = loadLocalChain(store, publicKey);
      if (maybeChain.isEmpty()) {
        LOG.error(
            "Validator {} has pending on-chain registration with commitment {} (activation epoch {}) but local hash chain file is missing or corrupted. Regeneration aborted for safety.",
            publicKey,
            pendingCommitment,
            status.activationEpoch().orElse(UInt64.ZERO));
        faultyValidators.add(publicKey);
        return SafeFuture.COMPLETE;
      }
      final HashChain chain = maybeChain.get();
      if (!chain.getCommitment().equals(pendingCommitment)) {
        LOG.error(
            "Validator {} has pending on-chain registration with commitment {} but local hash chain tip is {}. Mismatch detected; registration aborted for safety.",
            publicKey,
            pendingCommitment,
            chain.getCommitment());
        faultyValidators.add(publicKey);
        return SafeFuture.COMPLETE;
      }
      markSubmitted(publicKey, chain.getCommitment());
      return SafeFuture.COMPLETE;
    }

    // 3. If active on chain
    if (status.hasActiveCommitment()) {
      final Bytes32 activeCommitment = status.activeCommitment().orElseThrow();
      final Optional<HashChain> maybeChain = loadLocalChain(store, publicKey);
      if (maybeChain.isEmpty()) {
        LOG.error(
            "Validator {} has active on-chain commitment {} but local hash chain file is missing or corrupted. Regeneration aborted for safety.",
            publicKey,
            activeCommitment);
        faultyValidators.add(publicKey);
        return SafeFuture.COMPLETE;
      }
      final HashChain chain = maybeChain.get();
      if (chain.getRevealForCommitment(activeCommitment).isEmpty()) {
        LOG.error(
            "Validator {} has active on-chain commitment {} which cannot produce a next reveal from the local hash chain. Mismatch or exhausted chain detected; registration aborted for safety.",
            publicKey,
            activeCommitment);
        faultyValidators.add(publicKey);
        return SafeFuture.COMPLETE;
      }
      markSubmitted(publicKey, chain.getCommitment());
      return SafeFuture.COMPLETE;
    }

    // 4. Not registered in pool, pending, or active
    if (inFlightRegistrations.contains(publicKey)) {
      return SafeFuture.COMPLETE;
    }

    if (hashChainPasswordProvider.getPassword(publicKey).isEmpty()) {
      LOG.error(
          "Cannot generate or load hash chain for unregistered validator {}: no password available.",
          publicKey);
      return SafeFuture.COMPLETE;
    }

    return getOrGenerateHashChain(store, publicKey)
        .thenCompose(
            maybeChain -> {
              if (maybeChain.isEmpty()) {
                return SafeFuture.COMPLETE;
              }
              final HashChain chainToRegister = maybeChain.get();
              inFlightRegistrations.add(publicKey);
              return registerValidator(validator, chainToRegister)
                  .alwaysRun(() -> inFlightRegistrations.remove(publicKey))
                  .thenAccept(__ -> {});
            });
  }

  private SafeFuture<Optional<HashChain>> getOrGenerateHashChain(
      final HashChainStore store, final BLSPublicKey publicKey) {
    if (store.hasHashChain(publicKey)) {
      final Optional<HashChain> maybeChain = loadLocalChain(store, publicKey);
      if (maybeChain.isPresent()) {
        return SafeFuture.completedFuture(maybeChain);
      }
      return SafeFuture.completedFuture(Optional.empty());
    }

    return generationTaskQueue
        .<Optional<HashChain>>queueTask(
            () -> {
              if (store.hasHashChain(publicKey)) {
                final Optional<HashChain> existing = loadLocalChain(store, publicKey);
                if (existing.isPresent()) {
                  return SafeFuture.completedFuture(existing);
                }
                return SafeFuture.completedFuture(Optional.empty());
              }
              if (asyncRunner.isPresent()) {
                return asyncRunner
                    .get()
                    .runAsync(() -> Optional.of(doGenerateAndStore(store, publicKey)));
              } else {
                return SafeFuture.of(() -> Optional.of(doGenerateAndStore(store, publicKey)));
              }
            })
        .exceptionally(
            e -> {
              LOG.error(
                  "Failed to generate or store hash chain for validator {}: {}",
                  publicKey,
                  e.getMessage(),
                  e);
              return Optional.empty();
            });
  }

  private HashChain doGenerateAndStore(final HashChainStore store, final BLSPublicKey publicKey)
      throws Exception {
    if (store.hasHashChain(publicKey)) {
      throw new InvalidHashChainException(
          "Hash chain file already exists for validator " + publicKey + "; refusing to overwrite");
    }
    final Optional<String> maybePassword = hashChainPasswordProvider.getPassword(publicKey);
    if (maybePassword.isEmpty()) {
      throw new IllegalStateException(
          "Cannot generate hash chain: no password available for validator " + publicKey);
    }
    final HashChain generated = hashChainGenerator.generate();
    store.storeHashChain(publicKey, generated, maybePassword.get());
    LOG.info("Generated and stored new hash chain for validator {}", publicKey);
    return generated;
  }

  @VisibleForTesting
  ThrottlingTaskQueue getGenerationTaskQueue() {
    return generationTaskQueue;
  }

  private Optional<HashChain> loadLocalChain(
      final HashChainStore store, final BLSPublicKey publicKey) {
    if (!store.hasHashChain(publicKey)) {
      return Optional.empty();
    }
    final Optional<String> maybePassword = hashChainPasswordProvider.getPassword(publicKey);
    if (maybePassword.isEmpty()) {
      LOG.error(
          "Hash chain file exists for validator {} but no password is available. Registration aborted for safety.",
          publicKey);
      faultyValidators.add(publicKey);
      return Optional.empty();
    }
    try {
      return store.loadHashChain(publicKey, maybePassword.get());
    } catch (final Exception e) {
      LOG.error(
          "Hash chain file exists for validator {} but failed to load or decrypt: {}. Registration aborted for safety.",
          publicKey,
          e.getMessage());
      faultyValidators.add(publicKey);
      return Optional.empty();
    }
  }

  public boolean isAlreadySubmitted(final BLSPublicKey publicKey, final Bytes32 commitment) {
    checkNotNull(publicKey, "publicKey cannot be null");
    checkNotNull(commitment, "commitment cannot be null");
    return commitment.equals(submittedRegistrations.get(publicKey));
  }

  public void markSubmitted(final BLSPublicKey publicKey, final Bytes32 commitment) {
    checkNotNull(publicKey, "publicKey cannot be null");
    checkNotNull(commitment, "commitment cannot be null");
    submittedRegistrations.put(publicKey, commitment);
  }

  public boolean isFaulty(final BLSPublicKey publicKey) {
    return faultyValidators.contains(publicKey);
  }

  public Set<BLSPublicKey> getFaultyValidators() {
    return Collections.unmodifiableSet(faultyValidators);
  }

  public SafeFuture<SignedRandaoCommitmentRegistration> createSignedRegistration(
      final Validator validator,
      final UInt64 validatorIndex,
      final Bytes32 commitment,
      final Bytes32 genesisValidatorsRoot) {
    checkNotNull(validator, "validator cannot be null");
    checkNotNull(validatorIndex, "validatorIndex cannot be null");
    checkNotNull(commitment, "commitment cannot be null");
    checkNotNull(genesisValidatorsRoot, "genesisValidatorsRoot cannot be null");

    final RandaoCommitmentRegistration registration =
        new RandaoCommitmentRegistration(validatorIndex, commitment);
    return validator
        .getSigner()
        .signRandaoCommitmentRegistration(registration, genesisValidatorsRoot)
        .thenApply(signature -> new SignedRandaoCommitmentRegistration(registration, signature));
  }

  public SafeFuture<Optional<SignedRandaoCommitmentRegistration>> createSignedRegistration(
      final Validator validator, final HashChain hashChain) {
    checkNotNull(validator, "validator cannot be null");
    checkNotNull(hashChain, "hashChain cannot be null");

    final BLSPublicKey publicKey = validator.getPublicKey();
    final Bytes32 commitment = hashChain.getCommitment();

    return genesisDataProvider
        .getGenesisValidatorsRoot()
        .thenCompose(
            genesisValidatorsRoot ->
                getValidatorIndex(publicKey)
                    .thenCompose(
                        maybeIndex -> {
                          if (maybeIndex.isEmpty()) {
                            LOG.debug(
                                "Validator index for {} not yet known; skipping RANDAO commitment registration creation",
                                publicKey);
                            return SafeFuture.completedFuture(Optional.empty());
                          }
                          final UInt64 validatorIndex = UInt64.valueOf(maybeIndex.get());
                          return createSignedRegistration(
                                  validator, validatorIndex, commitment, genesisValidatorsRoot)
                              .thenApply(Optional::of);
                        }));
  }

  public SafeFuture<Void> submitRegistration(
      final SignedRandaoCommitmentRegistration signedRegistration) {
    checkNotNull(signedRegistration, "signedRegistration cannot be null");
    return validatorApiChannel.sendSignedRandaoCommitmentRegistration(signedRegistration);
  }

  public SafeFuture<Boolean> registerValidator(
      final Validator validator, final HashChain hashChain) {
    checkNotNull(validator, "validator cannot be null");
    checkNotNull(hashChain, "hashChain cannot be null");

    final BLSPublicKey publicKey = validator.getPublicKey();
    final Bytes32 commitment = hashChain.getCommitment();

    if (isAlreadySubmitted(publicKey, commitment)) {
      LOG.debug(
          "RANDAO commitment registration for validator {} with commitment {} was already submitted; skipping duplicate submission",
          publicKey,
          commitment);
      return SafeFuture.completedFuture(true);
    }

    return createSignedRegistration(validator, hashChain)
        .thenCompose(
            maybeRegistration -> {
              if (maybeRegistration.isEmpty()) {
                return SafeFuture.completedFuture(false);
              }
              final SignedRandaoCommitmentRegistration registration = maybeRegistration.get();
              return submitRegistration(registration)
                  .thenApply(
                      __ -> {
                        markSubmitted(publicKey, commitment);
                        LOG.info(
                            "Successfully submitted RANDAO commitment registration for validator {} (index {}) with commitment {}",
                            publicKey,
                            registration.getMessage().getValidatorIndex(),
                            commitment);
                        return true;
                      })
                  .exceptionally(
                      error -> {
                        LOG.warn(
                            "Failed to submit RANDAO commitment registration for validator {}: {}",
                            publicKey,
                            error.getMessage());
                        return false;
                      });
            })
        .exceptionally(
            error -> {
              LOG.warn(
                  "Error during RANDAO commitment registration for validator {}: {}",
                  publicKey,
                  error.getMessage());
              return false;
            });
  }

  public SafeFuture<Boolean> registerValidator(final Validator validator, final String password) {
    checkNotNull(validator, "validator cannot be null");
    checkNotNull(password, "password cannot be null");

    if (hashChainStore.isEmpty()) {
      LOG.warn(
          "No HashChainStore configured; cannot load hash chain for {}", validator.getPublicKey());
      return SafeFuture.completedFuture(false);
    }

    final Optional<HashChain> maybeHashChain;
    try {
      maybeHashChain = hashChainStore.get().loadHashChain(validator.getPublicKey(), password);
    } catch (final Exception e) {
      LOG.warn(
          "Failed to load hash chain for validator {}: {}",
          validator.getPublicKey(),
          e.getMessage());
      return SafeFuture.completedFuture(false);
    }

    if (maybeHashChain.isEmpty()) {
      LOG.debug("No stored hash chain found for validator {}", validator.getPublicKey());
      return SafeFuture.completedFuture(false);
    }

    return registerValidator(validator, maybeHashChain.get());
  }

  public SafeFuture<Map<BLSPublicKey, Boolean>> registerValidators(
      final Collection<Validator> validators,
      final Map<BLSPublicKey, HashChain> hashChainsByPubKey) {
    checkNotNull(validators, "validators cannot be null");
    checkNotNull(hashChainsByPubKey, "hashChainsByPubKey cannot be null");

    final Map<BLSPublicKey, Boolean> results = new ConcurrentHashMap<>();
    final List<SafeFuture<Void>> futures =
        validators.stream()
            .map(
                validator -> {
                  final HashChain hashChain = hashChainsByPubKey.get(validator.getPublicKey());
                  if (hashChain == null) {
                    results.put(validator.getPublicKey(), false);
                    return SafeFuture.COMPLETE;
                  }
                  return registerValidator(validator, hashChain)
                      .thenAccept(success -> results.put(validator.getPublicKey(), success));
                })
            .toList();

    return SafeFuture.allOf(futures.toArray(SafeFuture[]::new)).thenApply(__ -> results);
  }

  private SafeFuture<Optional<Integer>> getValidatorIndex(final BLSPublicKey publicKey) {
    return validatorIndexProvider
        .getValidatorIndicesByPublicKey()
        .thenApply(indices -> Optional.ofNullable(indices.get(publicKey)))
        .thenCompose(
            maybeIndex -> {
              if (maybeIndex.isPresent()) {
                return SafeFuture.completedFuture(maybeIndex);
              }
              return validatorApiChannel
                  .getValidatorIndices(List.of(publicKey))
                  .thenApply(indices -> Optional.ofNullable(indices.get(publicKey)));
            })
        .exceptionallyCompose(
            __ ->
                validatorApiChannel
                    .getValidatorIndices(List.of(publicKey))
                    .thenApply(indices -> Optional.ofNullable(indices.get(publicKey))));
  }
}
