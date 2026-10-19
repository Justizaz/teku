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

package tech.pegasys.teku.spec.config.builder;

import tech.pegasys.teku.spec.config.SpecConfigAndParent;
import tech.pegasys.teku.spec.config.SpecConfigEip8321;
import tech.pegasys.teku.spec.config.SpecConfigEip8321Impl;
import tech.pegasys.teku.spec.config.SpecConfigHeze;

import java.util.HashMap;
import java.util.Map;
import java.util.function.BiConsumer;

import static com.google.common.base.Preconditions.checkNotNull;

public class Eip8321Builder extends BaseForkBuilder
    implements ForkConfigBuilder<SpecConfigHeze, SpecConfigEip8321> {

  // eip8321 preset
  private Integer commitmentRegistrationDelay;
  private Integer maxRandaoCommitmentRegistrations;

  Eip8321Builder() {}

  @Override
  public SpecConfigAndParent<SpecConfigEip8321> build(
      final SpecConfigAndParent<SpecConfigHeze> specConfigAndParent) {
    return SpecConfigAndParent.of(
        new SpecConfigEip8321Impl(
            specConfigAndParent.specConfig(),
            commitmentRegistrationDelay,
            maxRandaoCommitmentRegistrations),
        specConfigAndParent);
  }

  public Eip8321Builder commitmentRegistrationDelay(final Integer commitmentRegistrationDelay) {
    checkNotNull(commitmentRegistrationDelay);
    this.commitmentRegistrationDelay = commitmentRegistrationDelay;
    return this;
  }

  public Eip8321Builder maxRandaoCommitmentRegistrations(final Integer maxRandaoCommitmentRegistrations) {
    checkNotNull(maxRandaoCommitmentRegistrations);
    this.maxRandaoCommitmentRegistrations = maxRandaoCommitmentRegistrations;
    return this;
  }

  @Override
  public void validate() {
    defaultValuesIfRequired(this);
    validateConstants();
  }

  @Override
  public Map<String, Object> getValidationMap() {
    final Map<String, Object> constants = new HashMap<>();
    constants.put("commitmentRegistrationDelay", commitmentRegistrationDelay);
    constants.put("maxRandaoCommitmentRegistrations", maxRandaoCommitmentRegistrations);
    return constants;
  }

  @Override
  public void addOverridableItemsToRawConfig(final BiConsumer<String, Object> rawConfig) {}
}
