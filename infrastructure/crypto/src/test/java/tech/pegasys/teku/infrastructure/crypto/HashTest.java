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

package tech.pegasys.teku.infrastructure.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class HashTest {

  /**
   * Authoritative test vectors from the official BLAKE3 specification and test suite
   * (https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json).
   *
   * <p>Inputs of length N are generated with repeating bytes: input[i] = (byte) (i % 251).
   */
  private static Bytes generateTestVectorInput(final int length) {
    final byte[] bytes = new byte[length];
    for (int i = 0; i < length; i++) {
      bytes[i] = (byte) (i % 251);
    }
    return Bytes.wrap(bytes);
  }

  @Test
  void blake3_shouldHashEmptyInputCorrectly() {
    final Bytes32 hash = Hash.blake3(Bytes.EMPTY);
    assertThat(hash)
        .isEqualTo(
            Bytes32.fromHexString(
                "0xaf1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"));
    assertThat(hash.size()).isEqualTo(32);
  }

  @ParameterizedTest(name = "BLAKE3 official test vector length {0}")
  @CsvSource({
    "0, 0xaf1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    "1, 0x2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
    "2, 0x7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63",
    "3, 0xe1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f",
    "64, 0x4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
    "65, 0xde1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
    "1024, 0x42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
    "1025, 0xd00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
    "2048, 0xe776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"
  })
  void blake3_shouldMatchOfficialTestVectors(final int inputLength, final String expectedHex) {
    final Bytes input = generateTestVectorInput(inputLength);
    final Bytes32 hash = Hash.blake3(input);
    assertThat(hash).isEqualTo(Bytes32.fromHexString(expectedHex));
    assertThat(hash.size()).isEqualTo(32);
  }

  @Test
  void blake3_shouldBeDeterministicAcrossRepeatedCalls() {
    final Bytes input = Bytes.wrap("DeterministicTestInput".getBytes(StandardCharsets.UTF_8));
    final Bytes32 first = Hash.blake3(input);
    final Bytes32 second = Hash.blake3(input);
    final Bytes32 third = Hash.blake3(input);

    assertThat(first).isEqualTo(second);
    assertThat(second).isEqualTo(third);
  }

  @Test
  void blake3_shouldBeThreadSafe() throws ExecutionException, InterruptedException {
    final int threadCount = 8;
    final int iterations = 1000;
    final ExecutorService executor = Executors.newFixedThreadPool(threadCount);
    try {
      final List<Callable<Void>> tasks = new ArrayList<>();
      for (int i = 0; i < threadCount; i++) {
        tasks.add(
            () -> {
              for (int j = 0; j < iterations; j++) {
                final Bytes32 emptyHash = Hash.blake3(Bytes.EMPTY);
                assertThat(emptyHash)
                    .isEqualTo(
                        Bytes32.fromHexString(
                            "0xaf1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"));

                final Bytes input65 = generateTestVectorInput(65);
                assertThat(Hash.blake3(input65))
                    .isEqualTo(
                        Bytes32.fromHexString(
                            "0xde1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"));
              }
              return null;
            });
      }
      final List<Future<Void>> futures = executor.invokeAll(tasks);
      for (final Future<Void> future : futures) {
        future.get();
      }
    } finally {
      executor.shutdown();
    }
  }

  @Test
  void sha256_shouldComputeCorrectHash() {
    final Bytes input = Bytes.wrap("hello".getBytes(StandardCharsets.UTF_8));
    final Bytes32 hash = Hash.sha256(input);
    assertThat(hash)
        .isEqualTo(
            Bytes32.fromHexString(
                "0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"));
  }

  @Test
  void keccak256_shouldComputeCorrectHash() {
    final Bytes input = Bytes.wrap("hello".getBytes(StandardCharsets.UTF_8));
    final Bytes32 hash = Hash.keccak256(input);
    assertThat(hash)
        .isEqualTo(
            Bytes32.fromHexString(
                "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"));
  }
}
