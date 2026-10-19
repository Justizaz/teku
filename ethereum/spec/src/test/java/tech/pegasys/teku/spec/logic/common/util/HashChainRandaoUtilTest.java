/*
 * Copyright Consensys Software Inc., 2026
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

package tech.pegasys.teku.spec.logic.common.util;

import static org.assertj.core.api.Assertions.assertThat;
import static tech.pegasys.teku.spec.logic.common.util.HashChainRandaoUtil.HASH_CHAIN_RANDAO_DST;

import java.nio.charset.StandardCharsets;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;
import tech.pegasys.teku.infrastructure.bytes.Bytes4;
import tech.pegasys.teku.infrastructure.crypto.Hash;
import tech.pegasys.teku.spec.constants.Domain;

public class HashChainRandaoUtilTest {

  private static final Bytes EXPECTED_DST =
      Bytes.fromHexString("0x484153485f434841494e5f52414e44414f");

  @Test
  void domainConstant_shouldMatchExpectedValue() {
    assertThat(Domain.DOMAIN_RANDAO_COMMITMENT_REGISTRATION)
        .isEqualTo(Bytes4.fromHexString("0x0F000000"));
  }

  @Test
  void dst_shouldMatchExpectedAsciiBytesAndLength() {
    assertThat(HASH_CHAIN_RANDAO_DST.size()).isEqualTo(17);
    assertThat(HASH_CHAIN_RANDAO_DST).isEqualTo(EXPECTED_DST);
    assertThat(HASH_CHAIN_RANDAO_DST)
        .isEqualTo(Bytes.wrap("HASH_CHAIN_RANDAO".getBytes(StandardCharsets.US_ASCII)));
  }

  @Test
  void computeCommitment_shouldComputeBlake3OverDstAndPreimage() {
    final Bytes32 preimage =
        Bytes32.fromHexString("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    final Bytes concatenated = Bytes.concatenate(HASH_CHAIN_RANDAO_DST, preimage);
    assertThat(concatenated.size()).isEqualTo(49);

    final Bytes32 expectedCommitment = Hash.blake3(concatenated);
    final Bytes32 actualCommitment = HashChainRandaoUtil.computeCommitment(preimage);

    assertThat(actualCommitment).isEqualTo(expectedCommitment);
    assertThat(actualCommitment.size()).isEqualTo(32);
  }

  @Test
  void verifyReveal_shouldAcceptValidPreimage() {
    final Bytes32 reveal =
        Bytes32.fromHexString("0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    final Bytes32 currentCommitment = HashChainRandaoUtil.computeCommitment(reveal);

    assertThat(HashChainRandaoUtil.verifyReveal(currentCommitment, reveal)).isTrue();
  }

  @Test
  void verifyReveal_shouldRejectZeroReveal() {
    // Zero reveal must be rejected even if current commitment is computed from zero preimage
    final Bytes32 zeroPreimageCommitment = HashChainRandaoUtil.computeCommitment(Bytes32.ZERO);
    assertThat(HashChainRandaoUtil.verifyReveal(zeroPreimageCommitment, Bytes32.ZERO)).isFalse();

    // Zero reveal against zero commitment must also be rejected
    assertThat(HashChainRandaoUtil.verifyReveal(Bytes32.ZERO, Bytes32.ZERO)).isFalse();
  }

  @Test
  void verifyReveal_shouldRejectInvalidPreimage() {
    final Bytes32 validReveal =
        Bytes32.fromHexString("0x1111111111111111111111111111111111111111111111111111111111111111");
    final Bytes32 invalidReveal =
        Bytes32.fromHexString("0x2222222222222222222222222222222222222222222222222222222222222222");

    final Bytes32 commitment = HashChainRandaoUtil.computeCommitment(validReveal);

    assertThat(HashChainRandaoUtil.verifyReveal(commitment, invalidReveal)).isFalse();
  }

  @Test
  void verifyReveal_shouldRejectWhenCommitmentDoesNotMatch() {
    final Bytes32 reveal =
        Bytes32.fromHexString("0x3333333333333333333333333333333333333333333333333333333333333333");
    final Bytes32 arbitraryCommitment =
        Bytes32.fromHexString("0x4444444444444444444444444444444444444444444444444444444444444444");

    assertThat(HashChainRandaoUtil.verifyReveal(arbitraryCommitment, reveal)).isFalse();
  }

  @Test
  void hashChain_shouldSupportMultiStepChainVerification() {
    final int chainLength = 5;
    final Bytes32[] chain = new Bytes32[chainLength];

    // Seed / bottom of hash chain (c_0)
    chain[0] =
        Bytes32.fromHexString("0x5555555555555555555555555555555555555555555555555555555555555555");

    // c_i = computeCommitment(c_{i-1})
    for (int i = 1; i < chainLength; i++) {
      chain[i] = HashChainRandaoUtil.computeCommitment(chain[i - 1]);
    }

    // Step-by-step verification: reveal c_{i-1} against commitment c_i
    for (int i = 1; i < chainLength; i++) {
      assertThat(HashChainRandaoUtil.verifyReveal(chain[i], chain[i - 1])).isTrue();
    }

    // Skipped-step / reversed reveals must fail
    assertThat(HashChainRandaoUtil.verifyReveal(chain[2], chain[0])).isFalse();
    assertThat(HashChainRandaoUtil.verifyReveal(chain[3], chain[1])).isFalse();
    assertThat(HashChainRandaoUtil.verifyReveal(chain[0], chain[1])).isFalse();
  }

  @Test
  void computeNextMix_shouldComputeBlake3OverConcatenated64Bytes() {
    final Bytes32 currentMix =
        Bytes32.fromHexString("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    final Bytes32 reveal =
        Bytes32.fromHexString("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    final Bytes concatenated = Bytes.concatenate(currentMix, reveal);
    assertThat(concatenated.size()).isEqualTo(64);

    final Bytes32 expectedMix = Hash.blake3(concatenated);
    final Bytes32 actualMix = HashChainRandaoUtil.computeNextMix(currentMix, reveal);

    assertThat(actualMix).isEqualTo(expectedMix);
    assertThat(actualMix.size()).isEqualTo(32);
  }

  @Test
  void computeNextMix_shouldBeNonCommutative() {
    final Bytes32 mixA =
        Bytes32.fromHexString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    final Bytes32 mixB =
        Bytes32.fromHexString("0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321");

    final Bytes32 mixAB = HashChainRandaoUtil.computeNextMix(mixA, mixB);
    final Bytes32 mixBA = HashChainRandaoUtil.computeNextMix(mixB, mixA);

    assertThat(mixAB).isNotEqualTo(mixBA);
  }
}
