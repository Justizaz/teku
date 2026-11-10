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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tech.pegasys.teku.bls.BLSKeyGenerator;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSPublicKey;
import tech.pegasys.teku.bls.keystore.KeyStoreValidationException;

public class HashChainStoreTest {

  private static final int FAST_PBKDF2_ITERATIONS = 1;
  private static final String PASSWORD = "test-password-123";

  @TempDir Path tempDir;

  private HashChainStore store;
  private BLSKeyPair keyPair;
  private BLSPublicKey publicKey;
  private HashChain hashChain;

  @BeforeEach
  void setUp() {
    store = new HashChainStore(tempDir, FAST_PBKDF2_ITERATIONS);
    keyPair = BLSKeyGenerator.generateKeyPairs(1).get(0);
    publicKey = keyPair.getPublicKey();
    final Bytes32 seed =
        Bytes32.fromHexString("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    hashChain = HashChainGenerator.generateFromSeed(seed, 10);
  }

  @Test
  void storeAndLoadHashChain_shouldPersistAndRestoreChainCorrectly() {
    store.storeHashChain(publicKey, hashChain, PASSWORD);

    assertThat(store.hasHashChain(publicKey)).isTrue();
    final Optional<HashChain> loaded = store.loadHashChain(publicKey, PASSWORD);

    assertThat(loaded).isPresent();
    final HashChain restored = loaded.get();
    assertThat(restored.getSeed()).isEqualTo(hashChain.getSeed());
    assertThat(restored.getLength()).isEqualTo(hashChain.getLength());
    assertThat(restored.getCommitment()).isEqualTo(hashChain.getCommitment());
    assertThat(restored.getLinks()).isEqualTo(hashChain.getLinks());
    assertThat(restored.verify()).isTrue();
  }

  @Test
  void storeHashChain_shouldEncryptAtRest() throws IOException {
    store.storeHashChain(publicKey, hashChain, PASSWORD);

    final Path storedPath = store.getPathForPublicKey(publicKey);
    assertThat(Files.isRegularFile(storedPath)).isTrue();

    final String rawJson = Files.readString(storedPath, UTF_8);
    assertThat(rawJson).contains("\"keystore\"");
    assertThat(rawJson).contains("\"crypto\"");
    assertThat(rawJson).contains("\"cipher\"");
    assertThat(rawJson).contains("\"checksum\"");
    assertThat(rawJson).contains("\"kdf\"");
    assertThat(rawJson).contains(publicKey.toBytesCompressed().toHexString());
    assertThat(rawJson).contains(hashChain.getCommitment().toHexString());

    // Plaintext seed must not appear anywhere in the stored file
    final String seedUnprefixed = hashChain.getSeed().toUnprefixedHexString();
    final String seedPrefixed = hashChain.getSeed().toHexString();
    assertThat(rawJson).doesNotContain(seedUnprefixed);
    assertThat(rawJson).doesNotContain(seedPrefixed);
  }

  @Test
  void persistenceAcrossRestart_shouldRestoreChainFromNewStoreInstance() {
    store.storeHashChain(publicKey, hashChain, PASSWORD);

    // Simulate restart by instantiating a completely new HashChainStore pointing to same directory
    final HashChainStore newStore = new HashChainStore(tempDir, FAST_PBKDF2_ITERATIONS);
    final Optional<HashChain> loaded = newStore.loadHashChain(publicKey, PASSWORD);

    assertThat(loaded).isPresent();
    assertThat(loaded.get().getSeed()).isEqualTo(hashChain.getSeed());
    assertThat(loaded.get().getCommitment()).isEqualTo(hashChain.getCommitment());
    assertThat(loaded.get().getLinks()).isEqualTo(hashChain.getLinks());
  }

  @Test
  void loadHashChain_withWrongPassword_shouldThrowKeyStoreValidationException() {
    store.storeHashChain(publicKey, hashChain, PASSWORD);

    assertThatThrownBy(() -> store.loadHashChain(publicKey, "wrong-password"))
        .isInstanceOf(KeyStoreValidationException.class)
        .hasMessageContaining("checksum validation failed");
  }

  @Test
  void loadHashChain_whenFileMissing_shouldReturnEmpty() {
    final BLSPublicKey nonExistentKey = BLSKeyGenerator.generateKeyPairs(1).get(0).getPublicKey();

    assertThat(store.hasHashChain(nonExistentKey)).isFalse();
    assertThat(store.loadHashChain(nonExistentKey, PASSWORD)).isEmpty();
    assertThat(store.loadHashChainData(nonExistentKey)).isEmpty();
    assertThat(store.getStoredCommitment(nonExistentKey)).isEmpty();
  }

  @Test
  void hasHashChain_and_deleteHashChain_shouldManageFileLifecycle() {
    assertThat(store.hasHashChain(publicKey)).isFalse();

    store.storeHashChain(publicKey, hashChain, PASSWORD);
    assertThat(store.hasHashChain(publicKey)).isTrue();

    final boolean deleted = store.deleteHashChain(publicKey);
    assertThat(deleted).isTrue();
    assertThat(store.hasHashChain(publicKey)).isFalse();

    final boolean deletedAgain = store.deleteHashChain(publicKey);
    assertThat(deletedAgain).isFalse();
  }

  @Test
  void getStoredValidatorPublicKeys_shouldListAllStoredKeys() {
    final List<BLSKeyPair> keyPairs = BLSKeyGenerator.generateKeyPairs(3);
    final BLSPublicKey key1 = keyPairs.get(0).getPublicKey();
    final BLSPublicKey key2 = keyPairs.get(1).getPublicKey();
    final BLSPublicKey key3 = keyPairs.get(2).getPublicKey();

    final HashChain chain1 = HashChainGenerator.generateFromSeed(Bytes32.fromHexString("0x01"), 5);
    final HashChain chain2 = HashChainGenerator.generateFromSeed(Bytes32.fromHexString("0x02"), 5);
    final HashChain chain3 = HashChainGenerator.generateFromSeed(Bytes32.fromHexString("0x03"), 5);

    store.storeHashChain(key1, chain1, PASSWORD);
    store.storeHashChain(key2, chain2, PASSWORD);
    store.storeHashChain(key3, chain3, PASSWORD);

    final List<BLSPublicKey> keys = store.getStoredValidatorPublicKeys();
    assertThat(keys).containsExactlyInAnyOrder(key1, key2, key3);
  }

  @Test
  void loadHashChainData_and_getStoredCommitment_withoutPassword() {
    store.storeHashChain(publicKey, hashChain, PASSWORD);

    final Optional<Bytes32> commitment = store.getStoredCommitment(publicKey);
    assertThat(commitment).contains(hashChain.getCommitment());

    final Optional<HashChainData> data = store.loadHashChainData(publicKey);
    assertThat(data).isPresent();
    assertThat(data.get().getPubkey()).isEqualTo(publicKey);
    assertThat(data.get().getLength()).isEqualTo(hashChain.getLength());
    assertThat(data.get().getCommitment()).isEqualTo(hashChain.getCommitment());
    assertThat(data.get().getVersion()).isEqualTo(HashChainData.CURRENT_VERSION);
  }

  @Test
  void loadHashChain_withCorruptedJson_shouldThrowInvalidHashChainException() throws IOException {
    store.storeHashChain(publicKey, hashChain, PASSWORD);

    final Path filePath = store.getPathForPublicKey(publicKey);
    Files.writeString(filePath, "{ invalid json content ...", UTF_8);

    assertThatThrownBy(() -> store.loadHashChain(publicKey, PASSWORD))
        .isInstanceOf(InvalidHashChainException.class)
        .hasMessageContaining("Corrupted hash chain data file");

    assertThatThrownBy(() -> store.loadHashChainData(publicKey))
        .isInstanceOf(InvalidHashChainException.class)
        .hasMessageContaining("Corrupted hash chain data file");
  }

  @Test
  void loadHashChain_withUnsupportedVersion_shouldThrowInvalidHashChainException()
      throws IOException {
    store.storeHashChain(publicKey, hashChain, PASSWORD);

    final Path filePath = store.getPathForPublicKey(publicKey);
    final String validJson = Files.readString(filePath, UTF_8);
    final String modifiedJson = validJson.replace("\"version\" : 1", "\"version\" : 99");
    Files.writeString(filePath, modifiedJson, UTF_8);

    assertThatThrownBy(() -> store.loadHashChain(publicKey, PASSWORD))
        .isInstanceOf(InvalidHashChainException.class)
        .hasMessageContaining("Unsupported hash chain version 99");
  }

  @Test
  void loadHashChain_withPublicKeyMismatch_shouldThrowInvalidHashChainException()
      throws IOException {
    store.storeHashChain(publicKey, hashChain, PASSWORD);

    final BLSPublicKey otherKey = BLSKeyGenerator.generateKeyPairs(1).get(0).getPublicKey();
    final Path otherPath = store.getPathForPublicKey(otherKey);

    // Copy original file to otherKey's file name
    Files.copy(store.getPathForPublicKey(publicKey), otherPath);

    assertThatThrownBy(() -> store.loadHashChain(otherKey, PASSWORD))
        .isInstanceOf(InvalidHashChainException.class)
        .hasMessageContaining("Public key mismatch");
  }

  @Test
  void loadHashChain_withCorruptedCommitment_shouldThrowInvalidHashChainException()
      throws IOException {
    store.storeHashChain(publicKey, hashChain, PASSWORD);

    final Path filePath = store.getPathForPublicKey(publicKey);
    final String validJson = Files.readString(filePath, UTF_8);
    final String wrongCommitment =
        "0x9999999999999999999999999999999999999999999999999999999999999999";
    final String modifiedJson =
        validJson.replace(hashChain.getCommitment().toHexString(), wrongCommitment);
    Files.writeString(filePath, modifiedJson, UTF_8);

    assertThatThrownBy(() -> store.loadHashChain(publicKey, PASSWORD))
        .isInstanceOf(InvalidHashChainException.class)
        .hasMessageContaining("Commitment mismatch");
  }

  @Test
  void storeHashChain_withInvalidLinksChain_shouldThrowInvalidHashChainException() {
    final HashChain corruptedChain =
        new HashChain(
            List.of(
                Bytes32.fromHexString("0x01"),
                Bytes32.fromHexString("0x02"),
                Bytes32.fromHexString("0x03")));

    assertThat(corruptedChain.verify()).isFalse();

    assertThatThrownBy(() -> store.storeHashChain(publicKey, corruptedChain, PASSWORD))
        .isInstanceOf(InvalidHashChainException.class)
        .hasMessageContaining("Cannot store an invalid hash chain");
  }

  @Test
  void storeHashChain_nullValidation_shouldThrowNullPointerException() {
    assertThatThrownBy(() -> store.storeHashChain(null, hashChain, PASSWORD))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> store.storeHashChain(publicKey, null, PASSWORD))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> store.storeHashChain(publicKey, hashChain, null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> store.loadHashChain(null, PASSWORD))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> store.loadHashChain(publicKey, null))
        .isInstanceOf(NullPointerException.class);
  }
}
