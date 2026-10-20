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

import java.nio.charset.StandardCharsets;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import tech.pegasys.teku.infrastructure.crypto.Hash;

public class HashChainRandaoUtil {

  public static final Bytes HASH_CHAIN_RANDAO_DST =
      Bytes.wrap("HASH_CHAIN_RANDAO".getBytes(StandardCharsets.US_ASCII));

  private HashChainRandaoUtil() {}

  public static Bytes32 computeCommitment(final Bytes32 preimage) {
    return Hash.blake3(Bytes.concatenate(HASH_CHAIN_RANDAO_DST, preimage));
  }

  public static boolean verifyReveal(final Bytes32 currentCommitment, final Bytes32 reveal) {
    if (reveal.isZero()) {
      return false;
    }
    return computeCommitment(reveal).equals(currentCommitment);
  }

  public static Bytes32 computeNextMix(final Bytes32 currentMix, final Bytes32 reveal) {
    return Hash.blake3(Bytes.concatenate(currentMix, reveal));
  }
}
