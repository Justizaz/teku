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

import java.security.MessageDigest;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.crypto.digests.Blake3Digest;

public class Hash {

  private static final ThreadLocal<MessageDigest> SHA256_MESSAGE_DIGEST_THREAD_LOCAL =
      ThreadLocal.withInitial(MessageDigestFactory::createSha256);

  private static final ThreadLocal<MessageDigest> KECCAK_256_MESSAGE_DIGEST_THREAD_LOCAL =
      ThreadLocal.withInitial(MessageDigestFactory::createKeccak256);

  // Note: We don't use varargs in these methods to avoid creating a Bytes[] instance.

  public static Bytes32 sha256(final byte[] input) {
    return Bytes32.wrap(SHA256_MESSAGE_DIGEST_THREAD_LOCAL.get().digest(input));
  }

  public static Bytes32 sha256(final Bytes input) {
    final MessageDigest digest = SHA256_MESSAGE_DIGEST_THREAD_LOCAL.get();
    input.update(digest);
    return Bytes32.wrap(digest.digest());
  }

  public static Bytes32 sha256(final Bytes a, final Bytes b) {
    final MessageDigest digest = SHA256_MESSAGE_DIGEST_THREAD_LOCAL.get();
    a.update(digest);
    b.update(digest);
    return Bytes32.wrap(digest.digest());
  }

  public static Bytes32 sha256(final Bytes a, final Bytes b, final Bytes c) {
    final MessageDigest digest = SHA256_MESSAGE_DIGEST_THREAD_LOCAL.get();
    a.update(digest);
    b.update(digest);
    c.update(digest);
    return Bytes32.wrap(digest.digest());
  }

  public static Bytes32 keccak256(final Bytes input) {
    final MessageDigest digest = KECCAK_256_MESSAGE_DIGEST_THREAD_LOCAL.get();
    input.update(digest);
    return Bytes32.wrap(digest.digest());
  }

  public static Bytes32 blake3(final Bytes input) {
    final Blake3Digest digest = new Blake3Digest();
    final byte[] inputBytes = input.toArrayUnsafe();
    digest.update(inputBytes, 0, inputBytes.length);
    final byte[] out = new byte[32];
    digest.doFinal(out, 0);
    return Bytes32.wrap(out);
  }

  /**
   * used when we need to do several hashing in loops, so we can query the thread local once and do
   * hashings
   *
   * @return Sha256
   */
  public static Sha256 getSha256Instance() {
    return new Sha256(SHA256_MESSAGE_DIGEST_THREAD_LOCAL.get());
  }
}
