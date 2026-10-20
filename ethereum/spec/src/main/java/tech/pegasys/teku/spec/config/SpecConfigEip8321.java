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

package tech.pegasys.teku.spec.config;

import java.util.Optional;

public interface SpecConfigEip8321 extends SpecConfigHeze {

  static SpecConfigEip8321 required(final SpecConfig specConfig) {
    return specConfig
            .toVersionEip8321()
            .orElseThrow(
                    () ->
                            new IllegalArgumentException(
                                    "Expected EIP-8321 spec config but got: " + specConfig.getClass().getSimpleName()));
  }

  int getCommitmentRegistrationDelay();

  int getMaxRandaoCommitmentRegistrations();

  @Override
  default Optional<SpecConfigEip8321> toVersionEip8321() {
    return Optional.of(this);
  }
}