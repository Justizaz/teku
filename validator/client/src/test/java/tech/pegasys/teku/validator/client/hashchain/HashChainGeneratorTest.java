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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;
import tech.pegasys.teku.spec.logic.common.util.HashChainRandaoUtil;

public class HashChainGeneratorTest {

  private final HashChainGenerator generator = new HashChainGenerator();

  @Test
  void generate_shouldGenerateChainWithDefaultLengthAndValidLinks() {
    final HashChain chain = generator.generate();

    assertThat(chain.getLength()).isEqualTo(HashChainGenerator.DEFAULT_CHAIN_LENGTH);
    assertThat(chain.size()).isEqualTo(HashChainGenerator.DEFAULT_CHAIN_LENGTH + 1);
    assertThat(chain.getSeed()).isNotEqualTo(Bytes32.ZERO);
    assertThat(chain.getCommitment()).isNotEqualTo(Bytes32.ZERO);
    assertThat(chain.getSeed()).isEqualTo(chain.getLink(0));
    assertThat(chain.getCommitment())
        .isEqualTo(chain.getLink(HashChainGenerator.DEFAULT_CHAIN_LENGTH));
    assertThat(chain.verify()).isTrue();
  }

  @Test
  void generate_withCustomLength_shouldGenerateValidChain() {
    final int customLength = 100;
    final HashChain chain = generator.generate(customLength);

    assertThat(chain.getLength()).isEqualTo(customLength);
    assertThat(chain.size()).isEqualTo(customLength + 1);
    assertThat(chain.getSeed()).isNotEqualTo(Bytes32.ZERO);
    assertThat(chain.getCommitment()).isNotEqualTo(Bytes32.ZERO);

    for (int i = 1; i <= customLength; i++) {
      final Bytes32 expected = HashChainRandaoUtil.computeCommitment(chain.getLink(i - 1));
      assertThat(chain.getLink(i)).isEqualTo(expected);
    }
    assertThat(chain.verify()).isTrue();
  }

  @Test
  void generateFromSeed_shouldGenerateDeterministicChain() {
    final Bytes32 seed =
        Bytes32.fromHexString("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    final int length = 5;

    final HashChain chain1 = HashChainGenerator.generateFromSeed(seed, length);
    final HashChain chain2 = HashChainGenerator.generateFromSeed(seed, length);

    assertThat(chain1).isEqualTo(chain2);
    assertThat(chain1.getSeed()).isEqualTo(seed);
    assertThat(chain1.getLength()).isEqualTo(5);
    assertThat(chain1.size()).isEqualTo(6);

    Bytes32 expected = seed;
    for (int i = 1; i <= length; i++) {
      expected = HashChainRandaoUtil.computeCommitment(expected);
      assertThat(chain1.getLink(i)).isEqualTo(expected);
    }
    assertThat(chain1.getCommitment()).isEqualTo(expected);
  }

  @Test
  void generate_shouldRejectInvalidLength() {
    assertThatThrownBy(() -> generator.generate(0))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Chain length must be at least 1");

    assertThatThrownBy(() -> generator.generate(-1)).isInstanceOf(IllegalArgumentException.class);

    assertThatThrownBy(() -> HashChainGenerator.generateFromSeed(Bytes32.fromHexString("0x01"), 0))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void generateFromSeed_shouldRejectZeroOrNullSeed() {
    assertThatThrownBy(() -> HashChainGenerator.generateFromSeed(null, 10))
        .isInstanceOf(IllegalArgumentException.class);

    assertThatThrownBy(() -> HashChainGenerator.generateFromSeed(Bytes32.ZERO, 10))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Seed must not be null or zero");
  }

  @Test
  @SuppressWarnings("DoNotCreateSecureRandomDirectly")
  void generate_shouldRegenerateIfSeedIsZero() {
    final AtomicInteger callCount = new AtomicInteger(0);
    final SecureRandom customRandom =
        new SecureRandom() {
          @Override
          public void nextBytes(final byte[] bytes) {
            if (callCount.getAndIncrement() == 0) {
              Arrays.fill(bytes, (byte) 0);
            } else {
              Arrays.fill(bytes, (byte) 1);
            }
          }
        };

    final HashChainGenerator customGenerator = new HashChainGenerator(customRandom);
    final HashChain chain = customGenerator.generate(5);

    assertThat(callCount.get()).isGreaterThanOrEqualTo(2);
    assertThat(chain.getSeed())
        .isEqualTo(
            Bytes32.fromHexString(
                "0x0101010101010101010101010101010101010101010101010101010101010101"));
    assertThat(chain.verify()).isTrue();
  }

  @Test
  void hashChain_shouldRetrieveRevealsInReverseOrder() {
    final Bytes32 seed =
        Bytes32.fromHexString("0x1111111111111111111111111111111111111111111111111111111111111111");
    final int length = 4;
    final HashChain chain = HashChainGenerator.generateFromSeed(seed, length);

    final Bytes32 c0 = chain.getLink(0);
    final Bytes32 c1 = chain.getLink(1);
    final Bytes32 c2 = chain.getLink(2);
    final Bytes32 c3 = chain.getLink(3);
    final Bytes32 c4 = chain.getLink(4);

    assertThat(chain.getCommitment()).isEqualTo(c4);
    assertThat(chain.getRevealsInOrder()).containsExactly(c3, c2, c1, c0);

    assertThat(chain.getRemainingReveals()).isEqualTo(4);
    assertThat(chain.getRevealedCount()).isEqualTo(0);
    assertThat(chain.isExhausted()).isFalse();

    assertThat(chain.peekNextReveal()).contains(c3);
    assertThat(chain.getNextReveal()).contains(c3);
    assertThat(chain.getRemainingReveals()).isEqualTo(3);
    assertThat(chain.getRevealedCount()).isEqualTo(1);

    assertThat(chain.getNextReveal()).contains(c2);
    assertThat(chain.getNextReveal()).contains(c1);
    assertThat(chain.getNextReveal()).contains(c0);

    assertThat(chain.isExhausted()).isTrue();
    assertThat(chain.getRemainingReveals()).isEqualTo(0);
    assertThat(chain.getRevealedCount()).isEqualTo(4);
    assertThat(chain.getNextReveal()).isEmpty();
    assertThat(chain.peekNextReveal()).isEmpty();
  }

  @Test
  void hashChain_getRevealBySequence_shouldReturnCorrectReveal() {
    final Bytes32 seed =
        Bytes32.fromHexString("0x2222222222222222222222222222222222222222222222222222222222222222");
    final int length = 3;
    final HashChain chain = HashChainGenerator.generateFromSeed(seed, length);

    assertThat(chain.getReveal(0)).contains(chain.getLink(2));
    assertThat(chain.getReveal(1)).contains(chain.getLink(1));
    assertThat(chain.getReveal(2)).contains(chain.getLink(0));
    assertThat(chain.getReveal(3)).isEmpty();
    assertThat(chain.getReveal(-1)).isEmpty();
  }

  @Test
  void hashChain_getRevealForCommitment_shouldReturnPredecessor() {
    final Bytes32 seed =
        Bytes32.fromHexString("0x3333333333333333333333333333333333333333333333333333333333333333");
    final int length = 4;
    final HashChain chain = HashChainGenerator.generateFromSeed(seed, length);

    final Bytes32 c4 = chain.getLink(4);
    final Bytes32 c3 = chain.getLink(3);
    final Bytes32 c2 = chain.getLink(2);
    final Bytes32 c1 = chain.getLink(1);
    final Bytes32 c0 = chain.getLink(0);

    assertThat(chain.getRevealForCommitment(c4)).contains(c3);
    assertThat(chain.getRevealForCommitment(c3)).contains(c2);
    assertThat(chain.getRevealForCommitment(c2)).contains(c1);
    assertThat(chain.getRevealForCommitment(c1)).contains(c0);
    assertThat(chain.getRevealForCommitment(c0)).isEmpty();
    assertThat(chain.getRevealForCommitment(Bytes32.ZERO)).isEmpty();
    assertThat(
            chain.getRevealForCommitment(
                Bytes32.fromHexString(
                    "0x9999999999999999999999999999999999999999999999999999999999999999")))
        .isEmpty();
  }

  @Test
  void hashChain_cursorManagement() {
    final Bytes32 seed =
        Bytes32.fromHexString("0x4444444444444444444444444444444444444444444444444444444444444444");
    final HashChain chain = HashChainGenerator.generateFromSeed(seed, 5);

    chain.getNextReveal();
    chain.getNextReveal();
    assertThat(chain.getRevealedCount()).isEqualTo(2);

    chain.resetRevealCursor();
    assertThat(chain.getRevealedCount()).isEqualTo(0);
    assertThat(chain.getNextReveal()).contains(chain.getLink(4));

    assertThat(chain.setRevealCursor(3)).isTrue();
    assertThat(chain.getRevealedCount()).isEqualTo(3);
    assertThat(chain.getNextReveal()).contains(chain.getLink(1));

    assertThat(chain.setRevealCursor(-1)).isFalse();
    assertThat(chain.setRevealCursor(10)).isFalse();
  }

  @Test
  void hashChain_constructorRejectsInvalidLinks() {
    assertThatThrownBy(() -> new HashChain(null)).isInstanceOf(IllegalArgumentException.class);

    assertThatThrownBy(() -> new HashChain(List.of(Bytes32.fromHexString("0x01"))))
        .isInstanceOf(IllegalArgumentException.class);

    final List<Bytes32> zeroLinkList =
        new ArrayList<>(
            List.of(Bytes32.fromHexString("0x01"), Bytes32.ZERO, Bytes32.fromHexString("0x02")));
    assertThatThrownBy(() -> new HashChain(zeroLinkList))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("must not be zero");
  }

  @Test
  void hashChain_verifyShouldDetectCorruptedLinks() {
    final Bytes32 seed =
        Bytes32.fromHexString("0x5555555555555555555555555555555555555555555555555555555555555555");
    final HashChain validChain = HashChainGenerator.generateFromSeed(seed, 3);
    assertThat(validChain.verify()).isTrue();

    final List<Bytes32> corruptedLinks = new ArrayList<>(validChain.getLinks());
    corruptedLinks.set(
        2,
        Bytes32.fromHexString(
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    final HashChain corruptedChain = new HashChain(corruptedLinks);
    assertThat(corruptedChain.verify()).isFalse();
  }
}
