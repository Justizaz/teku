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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.MoreObjects;
import java.util.Objects;
import org.apache.tuweni.bytes.Bytes32;
import tech.pegasys.teku.bls.BLSPublicKey;
import tech.pegasys.teku.bls.keystore.KeyStoreValidationException;
import tech.pegasys.teku.bls.keystore.model.KeyStoreData;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class HashChainData {
  public static final int CURRENT_VERSION = 1;

  private final int version;
  private final BLSPublicKey pubkey;
  private final int length;
  private final Bytes32 commitment;
  private final KeyStoreData keystore;

  @JsonCreator
  public HashChainData(
      @JsonProperty(value = "version", required = true) final int version,
      @JsonProperty(value = "pubkey", required = true) final BLSPublicKey pubkey,
      @JsonProperty(value = "length", required = true) final int length,
      @JsonProperty(value = "commitment", required = true) final Bytes32 commitment,
      @JsonProperty(value = "keystore", required = true) final KeyStoreData keystore) {
    this.version = version;
    this.pubkey = pubkey;
    this.length = length;
    this.commitment = commitment;
    this.keystore = keystore;
  }

  public int getVersion() {
    return version;
  }

  public BLSPublicKey getPubkey() {
    return pubkey;
  }

  public int getLength() {
    return length;
  }

  public Bytes32 getCommitment() {
    return commitment;
  }

  public KeyStoreData getKeystore() {
    return keystore;
  }

  public void validate() throws InvalidHashChainException {
    if (version != CURRENT_VERSION) {
      throw new InvalidHashChainException(
          String.format(
              "Unsupported hash chain version %d, expected %d", version, CURRENT_VERSION));
    }
    if (pubkey == null) {
      throw new InvalidHashChainException("Validator public key cannot be null");
    }
    if (length < 1) {
      throw new InvalidHashChainException(
          String.format("Invalid hash chain length %d, must be >= 1", length));
    }
    if (commitment == null || commitment.isZero()) {
      throw new InvalidHashChainException("Hash chain commitment cannot be null or zero");
    }
    if (keystore == null) {
      throw new InvalidHashChainException("Keystore data cannot be null");
    }
    try {
      keystore.validate();
    } catch (final KeyStoreValidationException e) {
      throw new InvalidHashChainException("Invalid keystore data: " + e.getMessage(), e);
    }
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    final HashChainData that = (HashChainData) o;
    return version == that.version
        && length == that.length
        && Objects.equals(pubkey, that.pubkey)
        && Objects.equals(commitment, that.commitment)
        && Objects.equals(keystore, that.keystore);
  }

  @Override
  public int hashCode() {
    return Objects.hash(version, pubkey, length, commitment, keystore);
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("version", version)
        .add("pubkey", pubkey)
        .add("length", length)
        .add("commitment", commitment)
        .add("keystore", keystore)
        .toString();
  }
}
