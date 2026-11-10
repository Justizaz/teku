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

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes32;
import tech.pegasys.teku.bls.BLSPublicKey;
import tech.pegasys.teku.infrastructure.async.SafeFuture;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.datastructures.operations.RandaoCommitmentRegistration;
import tech.pegasys.teku.spec.datastructures.operations.SignedRandaoCommitmentRegistration;
import tech.pegasys.teku.validator.api.ValidatorApiChannel;
import tech.pegasys.teku.validator.beaconnode.GenesisDataProvider;
import tech.pegasys.teku.validator.client.Validator;
import tech.pegasys.teku.validator.client.ValidatorIndexProvider;

public class RandaoCommitmentRegistrator {
  private static final Logger LOG = LogManager.getLogger();

  private final ValidatorApiChannel validatorApiChannel;
  private final ValidatorIndexProvider validatorIndexProvider;
  private final GenesisDataProvider genesisDataProvider;
  private final Optional<HashChainStore> hashChainStore;
  private final Map<BLSPublicKey, Bytes32> submittedRegistrations = new ConcurrentHashMap<>();

  public RandaoCommitmentRegistrator(
      final ValidatorApiChannel validatorApiChannel,
      final ValidatorIndexProvider validatorIndexProvider,
      final GenesisDataProvider genesisDataProvider) {
    this(validatorApiChannel, validatorIndexProvider, genesisDataProvider, Optional.empty());
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
        Optional.ofNullable(hashChainStore));
  }

  private RandaoCommitmentRegistrator(
      final ValidatorApiChannel validatorApiChannel,
      final ValidatorIndexProvider validatorIndexProvider,
      final GenesisDataProvider genesisDataProvider,
      final Optional<HashChainStore> hashChainStore) {
    this.validatorApiChannel =
        checkNotNull(validatorApiChannel, "validatorApiChannel cannot be null");
    this.validatorIndexProvider =
        checkNotNull(validatorIndexProvider, "validatorIndexProvider cannot be null");
    this.genesisDataProvider =
        checkNotNull(genesisDataProvider, "genesisDataProvider cannot be null");
    this.hashChainStore = checkNotNull(hashChainStore, "hashChainStore cannot be null");
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
