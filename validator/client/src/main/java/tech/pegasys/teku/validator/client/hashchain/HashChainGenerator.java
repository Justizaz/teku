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

import static com.google.common.base.Preconditions.checkArgument;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import org.apache.tuweni.bytes.Bytes32;
import tech.pegasys.teku.infrastructure.crypto.SecureRandomProvider;
import tech.pegasys.teku.spec.logic.common.util.HashChainRandaoUtil;

public class HashChainGenerator {
  public static final int DEFAULT_CHAIN_LENGTH = 65_536;

  private final SecureRandom secureRandom;

  public HashChainGenerator() {
    this(SecureRandomProvider.createSecureRandom());
  }

  public HashChainGenerator(final SecureRandom secureRandom) {
    this.secureRandom = secureRandom;
  }

  /** Generates a hash chain with the default recommended length (65,536). */
  public HashChain generate() {
    return generate(DEFAULT_CHAIN_LENGTH);
  }

  /**
   * Generates a hash chain with the specified length using SecureRandom. Ensures that neither the
   * seed nor any computed link is zero. If any link is zero, the entire chain is regenerated.
   */
  public HashChain generate(final int length) {
    checkArgument(length >= 1, "Chain length must be at least 1");
    while (true) {
      final Bytes32 seed = generateRandomSeed();
      if (seed.isZero()) {
        continue;
      }
      final HashChain chain = tryGenerateFromSeed(seed, length);
      if (chain != null) {
        return chain;
      }
    }
  }

  /**
   * Generates a hash chain deterministically from a given seed. Throws an exception if the seed or
   * any derived link is zero.
   */
  public static HashChain generateFromSeed(final Bytes32 seed, final int length) {
    checkArgument(seed != null && !seed.isZero(), "Seed must not be null or zero");
    checkArgument(length >= 1, "Chain length must be at least 1");
    final HashChain chain = tryGenerateFromSeed(seed, length);
    if (chain == null) {
      throw new IllegalStateException("Generated hash chain contains a zero link");
    }
    return chain;
  }

  private Bytes32 generateRandomSeed() {
    final byte[] seedBytes = new byte[32];
    secureRandom.nextBytes(seedBytes);
    return Bytes32.wrap(seedBytes);
  }

  private static HashChain tryGenerateFromSeed(final Bytes32 seed, final int length) {
    if (seed.isZero()) {
      return null;
    }
    final List<Bytes32> links = new ArrayList<>(length + 1);
    links.add(seed);
    Bytes32 current = seed;
    for (int i = 1; i <= length; i++) {
      current = HashChainRandaoUtil.computeCommitment(current);
      if (current.isZero()) {
        return null;
      }
      links.add(current);
    }
    return new HashChain(links);
  }
}
