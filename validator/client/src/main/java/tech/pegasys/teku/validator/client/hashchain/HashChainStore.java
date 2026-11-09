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
import static java.nio.charset.StandardCharsets.UTF_8;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import tech.pegasys.teku.bls.BLSPublicKey;
import tech.pegasys.teku.bls.keystore.KeyStore;
import tech.pegasys.teku.bls.keystore.KeyStoreValidationException;
import tech.pegasys.teku.bls.keystore.model.Cipher;
import tech.pegasys.teku.bls.keystore.model.CipherFunction;
import tech.pegasys.teku.bls.keystore.model.KdfParam;
import tech.pegasys.teku.bls.keystore.model.KeyStoreData;
import tech.pegasys.teku.bls.keystore.model.Pbkdf2Param;
import tech.pegasys.teku.bls.keystore.model.Pbkdf2PseudoRandomFunction;
import tech.pegasys.teku.infrastructure.crypto.SecureRandomProvider;
import tech.pegasys.teku.service.serviceutils.layout.DataDirLayout;
import tech.pegasys.teku.validator.client.ValidatorClientService;

public class HashChainStore {
  public static final int DEFAULT_PBKDF2_ITERATIONS = 262_144;
  private static final String FILE_EXTENSION = ".json";

  private final Path storageDirectory;
  private final SecureRandom secureRandom;
  private final int pbkdf2Iterations;
  private final ObjectMapper objectMapper;

  public HashChainStore(final Path storageDirectory) {
    this(storageDirectory, SecureRandomProvider.createSecureRandom(), DEFAULT_PBKDF2_ITERATIONS);
  }

  public HashChainStore(final Path storageDirectory, final int pbkdf2Iterations) {
    this(storageDirectory, SecureRandomProvider.createSecureRandom(), pbkdf2Iterations);
  }

  public HashChainStore(
      final Path storageDirectory, final SecureRandom secureRandom, final int pbkdf2Iterations) {
    this.storageDirectory = checkNotNull(storageDirectory, "Storage directory cannot be null");
    this.secureRandom = checkNotNull(secureRandom, "SecureRandom cannot be null");
    this.pbkdf2Iterations = pbkdf2Iterations;
    this.objectMapper = createObjectMapper();
  }

  public static HashChainStore fromDataDirLayout(final DataDirLayout dataDirLayout) {
    return new HashChainStore(ValidatorClientService.getHashChainStoragePath(dataDirLayout));
  }

  public static HashChainStore fromDataDirLayout(
      final DataDirLayout dataDirLayout, final int pbkdf2Iterations) {
    return new HashChainStore(
        ValidatorClientService.getHashChainStoragePath(dataDirLayout), pbkdf2Iterations);
  }

  public Path getStorageDirectory() {
    return storageDirectory;
  }

  public Path getPathForPublicKey(final BLSPublicKey publicKey) {
    checkNotNull(publicKey, "Public key cannot be null");
    final String fileName = publicKey.toBytesCompressed().toUnprefixedHexString() + FILE_EXTENSION;
    return storageDirectory.resolve(fileName);
  }

  public boolean hasHashChain(final BLSPublicKey publicKey) {
    checkNotNull(publicKey, "Public key cannot be null");
    return Files.isRegularFile(getPathForPublicKey(publicKey));
  }

  public void storeHashChain(
      final BLSPublicKey publicKey, final HashChain hashChain, final String password)
      throws InvalidHashChainException, KeyStoreValidationException {
    checkNotNull(publicKey, "Public key cannot be null");
    checkNotNull(hashChain, "Hash chain cannot be null");
    checkNotNull(password, "Password cannot be null");

    if (!hashChain.verify()) {
      throw new InvalidHashChainException("Cannot store an invalid hash chain");
    }

    final KdfParam kdfParam =
        new Pbkdf2Param(
            32,
            pbkdf2Iterations,
            Pbkdf2PseudoRandomFunction.HMAC_SHA256,
            Bytes32.random(secureRandom));
    final Cipher cipher = new Cipher(CipherFunction.AES_128_CTR, Bytes.random(16, secureRandom));

    final KeyStoreData keyStoreData =
        KeyStore.encrypt(
            hashChain.getSeed(),
            publicKey.toBytesCompressed(),
            password,
            "hashchain/" + hashChain.getLength(),
            kdfParam,
            cipher);

    final HashChainData hashChainData =
        new HashChainData(
            HashChainData.CURRENT_VERSION,
            publicKey,
            hashChain.getLength(),
            hashChain.getCommitment(),
            keyStoreData);

    final Path targetPath = getPathForPublicKey(publicKey);
    final String tempFileName = "." + targetPath.getFileName().toString() + ".tmp";
    final Path tempPath = storageDirectory.resolve(tempFileName);

    try {
      Files.createDirectories(storageDirectory);
      final String json =
          objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(hashChainData);
      Files.writeString(tempPath, json, UTF_8);
      try {
        Files.move(
            tempPath,
            targetPath,
            StandardCopyOption.ATOMIC_MOVE,
            StandardCopyOption.REPLACE_EXISTING);
      } catch (final AtomicMoveNotSupportedException e) {
        Files.move(tempPath, targetPath, StandardCopyOption.REPLACE_EXISTING);
      }
    } catch (final IOException e) {
      try {
        Files.deleteIfExists(tempPath);
      } catch (final IOException ignored) {
        // ignore cleanup error
      }
      throw new InvalidHashChainException("Failed to persist hash chain for " + publicKey, e);
    }
  }

  public Optional<HashChain> loadHashChain(final BLSPublicKey publicKey, final String password)
      throws InvalidHashChainException, KeyStoreValidationException {
    checkNotNull(publicKey, "Public key cannot be null");
    checkNotNull(password, "Password cannot be null");

    final Path filePath = getPathForPublicKey(publicKey);
    if (!Files.isRegularFile(filePath)) {
      return Optional.empty();
    }

    final HashChainData hashChainData = readHashChainData(filePath, publicKey);
    hashChainData.validate();

    if (!hashChainData.getPubkey().equals(publicKey)) {
      throw new InvalidHashChainException(
          String.format(
              "Public key mismatch: expected %s but found %s in stored record",
              publicKey, hashChainData.getPubkey()));
    }

    final Bytes decryptedSeedBytes = KeyStore.decrypt(password, hashChainData.getKeystore());
    if (decryptedSeedBytes.size() != 32 || decryptedSeedBytes.isZero()) {
      throw new InvalidHashChainException("Decrypted seed is invalid (size or value is zero)");
    }

    final Bytes32 seed = Bytes32.wrap(decryptedSeedBytes);
    final HashChain hashChain;
    try {
      hashChain = HashChainGenerator.generateFromSeed(seed, hashChainData.getLength());
    } catch (final Exception e) {
      throw new InvalidHashChainException(
          "Failed to regenerate hash chain from decrypted seed: " + e.getMessage(), e);
    }

    if (!hashChain.getCommitment().equals(hashChainData.getCommitment())) {
      throw new InvalidHashChainException(
          String.format(
              "Commitment mismatch: regenerated %s does not match stored %s",
              hashChain.getCommitment(), hashChainData.getCommitment()));
    }

    if (!hashChain.verify()) {
      throw new InvalidHashChainException("Regenerated hash chain links verification failed");
    }

    return Optional.of(hashChain);
  }

  public Optional<HashChainData> loadHashChainData(final BLSPublicKey publicKey)
      throws InvalidHashChainException {
    checkNotNull(publicKey, "Public key cannot be null");
    final Path filePath = getPathForPublicKey(publicKey);
    if (!Files.isRegularFile(filePath)) {
      return Optional.empty();
    }
    final HashChainData data = readHashChainData(filePath, publicKey);
    data.validate();
    return Optional.of(data);
  }

  public Optional<Bytes32> getStoredCommitment(final BLSPublicKey publicKey)
      throws InvalidHashChainException {
    return loadHashChainData(publicKey).map(HashChainData::getCommitment);
  }

  public boolean deleteHashChain(final BLSPublicKey publicKey) {
    checkNotNull(publicKey, "Public key cannot be null");
    final Path filePath = getPathForPublicKey(publicKey);
    try {
      return Files.deleteIfExists(filePath);
    } catch (final IOException e) {
      throw new InvalidHashChainException("Failed to delete hash chain file for " + publicKey, e);
    }
  }

  public List<BLSPublicKey> getStoredValidatorPublicKeys() {
    if (!Files.isDirectory(storageDirectory)) {
      return Collections.emptyList();
    }
    try (final Stream<Path> stream = Files.list(storageDirectory)) {
      final List<BLSPublicKey> publicKeys = new ArrayList<>();
      stream
          .filter(Files::isRegularFile)
          .filter(path -> path.getFileName().toString().endsWith(FILE_EXTENSION))
          .filter(path -> !path.getFileName().toString().startsWith("."))
          .forEach(
              path -> {
                final String fileName = path.getFileName().toString();
                final String hexString =
                    fileName.substring(0, fileName.length() - FILE_EXTENSION.length());
                try {
                  final BLSPublicKey pubKey = BLSPublicKey.fromHexString("0x" + hexString);
                  publicKeys.add(pubKey);
                } catch (final Exception ignored) {
                  // ignore non-key files
                }
              });
      return Collections.unmodifiableList(publicKeys);
    } catch (final IOException e) {
      throw new InvalidHashChainException(
          "Failed to list stored hash chain files in " + storageDirectory, e);
    }
  }

  private HashChainData readHashChainData(final Path filePath, final BLSPublicKey publicKey) {
    try {
      final String json = Files.readString(filePath, UTF_8);
      return objectMapper.readValue(json, HashChainData.class);
    } catch (final JsonProcessingException | IllegalArgumentException e) {
      throw new InvalidHashChainException("Corrupted hash chain data file for " + publicKey, e);
    } catch (final IOException e) {
      throw new InvalidHashChainException("IO error reading hash chain file for " + publicKey, e);
    }
  }

  private static ObjectMapper createObjectMapper() {
    final ObjectMapper mapper = new ObjectMapper();
    final SimpleModule module = new SimpleModule("HashChainStore");

    module.addSerializer(
        Bytes.class,
        new JsonSerializer<>() {
          @Override
          public void serialize(
              final Bytes value, final JsonGenerator gen, final SerializerProvider serializers)
              throws IOException {
            gen.writeString(value.toHexString());
          }
        });
    module.addDeserializer(
        Bytes.class,
        new JsonDeserializer<>() {
          @Override
          public Bytes deserialize(final JsonParser p, final DeserializationContext ctxt)
              throws IOException {
            final String val = p.getValueAsString();
            return val != null ? Bytes.fromHexString(val) : null;
          }
        });

    module.addSerializer(
        Bytes32.class,
        new JsonSerializer<>() {
          @Override
          public void serialize(
              final Bytes32 value, final JsonGenerator gen, final SerializerProvider serializers)
              throws IOException {
            gen.writeString(value.toHexString());
          }
        });
    module.addDeserializer(
        Bytes32.class,
        new JsonDeserializer<>() {
          @Override
          public Bytes32 deserialize(final JsonParser p, final DeserializationContext ctxt)
              throws IOException {
            final String val = p.getValueAsString();
            return val != null ? Bytes32.fromHexString(val) : null;
          }
        });

    module.addSerializer(
        BLSPublicKey.class,
        new JsonSerializer<>() {
          @Override
          public void serialize(
              final BLSPublicKey value,
              final JsonGenerator gen,
              final SerializerProvider serializers)
              throws IOException {
            gen.writeString(value.toHexString());
          }
        });
    module.addDeserializer(
        BLSPublicKey.class,
        new JsonDeserializer<>() {
          @Override
          public BLSPublicKey deserialize(final JsonParser p, final DeserializationContext ctxt)
              throws IOException {
            final String val = p.getValueAsString();
            return val != null ? BLSPublicKey.fromHexString(val) : null;
          }
        });

    mapper.registerModule(module);
    mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    return mapper;
  }
}
