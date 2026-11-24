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

package tech.pegasys.teku.spec.datastructures.operations;

import static org.assertj.core.api.Assertions.assertThat;

import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;
import tech.pegasys.teku.bls.BLSSignature;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;

class SignedRandaoCommitmentRegistrationTest {
  @Test
  void shouldSerializeAndDeserializeCorrectly() {
    final RandaoCommitmentRegistration message =
        new RandaoCommitmentRegistration(UInt64.valueOf(42), Bytes32.ZERO);

    final SignedRandaoCommitmentRegistration registration =
        new SignedRandaoCommitmentRegistration(message, BLSSignature.empty());

    assertThat(registration.getMessage()).isEqualTo(message);
    assertThat(registration.getSignature()).isEqualTo(BLSSignature.empty());

    final SignedRandaoCommitmentRegistration deserialized =
        SignedRandaoCommitmentRegistration.SSZ_SCHEMA.sszDeserialize(registration.sszSerialize());

    assertThat(deserialized).isEqualTo(registration);
  }
}
