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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.tuweni.bytes.Bytes32;
import tech.pegasys.teku.spec.logic.common.util.HashChainRandaoUtil;

public class HashChain {
  private final List<Bytes32> links;
  private final int length;
  private final AtomicInteger revealCursor = new AtomicInteger(0);

  public HashChain(final List<Bytes32> links) {
    checkArgument(
        links != null && links.size() >= 2,
        "Hash chain must contain at least a seed and one commitment (length >= 1)");
    for (int i = 0; i < links.size(); i++) {
      checkArgument(!links.get(i).isZero(), "Hash chain link at index %s must not be zero", i);
    }
    this.links = List.copyOf(links);
    this.length = links.size() - 1;
  }

  public Bytes32 getSeed() {
    return links.get(0);
  }

  public Bytes32 getCommitment() {
    return links.get(length);
  }

  public int getLength() {
    return length;
  }

  public int size() {
    return links.size();
  }

  public List<Bytes32> getLinks() {
    return links;
  }

  public Bytes32 getLink(final int index) {
    checkArgument(
        index >= 0 && index <= length, "Index %s out of bounds for chain length %s", index, length);
    return links.get(index);
  }

  /** Returns reveals in the order they must be revealed: c_{n-1}, c_{n-2}, ..., c_0. */
  public List<Bytes32> getRevealsInOrder() {
    final List<Bytes32> reveals = new ArrayList<>(length);
    for (int i = length - 1; i >= 0; i--) {
      reveals.add(links.get(i));
    }
    return Collections.unmodifiableList(reveals);
  }

  /**
   * Returns the reveal at the specified sequence number (0-indexed). 0 -> c_{n-1}, 1 -> c_{n-2},
   * ..., n-1 -> c_0.
   */
  public Optional<Bytes32> getReveal(final int sequenceNumber) {
    if (sequenceNumber < 0 || sequenceNumber >= length) {
      return Optional.empty();
    }
    return Optional.of(links.get(length - 1 - sequenceNumber));
  }

  /**
   * Retrieves the next reveal given the on-chain current commitment c_k. If currentCommitment is
   * c_k for k > 0, the next reveal is c_{k-1}. If currentCommitment is c_0, the chain is exhausted.
   */
  public Optional<Bytes32> getRevealForCommitment(final Bytes32 currentCommitment) {
    if (currentCommitment == null || currentCommitment.isZero()) {
      return Optional.empty();
    }
    for (int i = length; i >= 1; i--) {
      if (links.get(i).equals(currentCommitment)) {
        return Optional.of(links.get(i - 1));
      }
    }
    return Optional.empty();
  }

  /** Retrieves the next reveal in reverse order and advances the internal cursor. */
  public Optional<Bytes32> getNextReveal() {
    final int nextIndex = revealCursor.getAndIncrement();
    if (nextIndex >= length) {
      return Optional.empty();
    }
    return Optional.of(links.get(length - 1 - nextIndex));
  }

  /** Peeks at the next reveal in reverse order without advancing the internal cursor. */
  public Optional<Bytes32> peekNextReveal() {
    final int nextIndex = revealCursor.get();
    if (nextIndex >= length) {
      return Optional.empty();
    }
    return Optional.of(links.get(length - 1 - nextIndex));
  }

  public int getRevealedCount() {
    return Math.min(revealCursor.get(), length);
  }

  public int getRemainingReveals() {
    return Math.max(0, length - revealCursor.get());
  }

  public boolean isExhausted() {
    return getRemainingReveals() == 0;
  }

  public void resetRevealCursor() {
    revealCursor.set(0);
  }

  public boolean setRevealCursor(final int position) {
    if (position < 0 || position > length) {
      return false;
    }
    revealCursor.set(position);
    return true;
  }

  public boolean verify() {
    for (int i = 1; i <= length; i++) {
      if (!HashChainRandaoUtil.verifyReveal(links.get(i), links.get(i - 1))) {
        return false;
      }
    }
    return true;
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    final HashChain hashChain = (HashChain) o;
    return links.equals(hashChain.links);
  }

  @Override
  public int hashCode() {
    return Objects.hash(links);
  }

  @Override
  public String toString() {
    return "HashChain{"
        + "length="
        + length
        + ", seed="
        + getSeed()
        + ", commitment="
        + getCommitment()
        + ", remainingReveals="
        + getRemainingReveals()
        + '}';
  }
}
