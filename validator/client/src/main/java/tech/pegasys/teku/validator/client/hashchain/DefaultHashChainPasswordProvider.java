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

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import tech.pegasys.teku.bls.BLSPublicKey;

public class DefaultHashChainPasswordProvider implements HashChainPasswordProvider {

  private final Map<BLSPublicKey, Supplier<String>> passwordSuppliers = new ConcurrentHashMap<>();

  @Override
  public Optional<String> getPassword(final BLSPublicKey publicKey) {
    final Supplier<String> supplier = passwordSuppliers.get(publicKey);
    if (supplier == null) {
      return Optional.empty();
    }
    return Optional.ofNullable(supplier.get());
  }

  public void addPasswordSupplier(final BLSPublicKey publicKey, final Supplier<String> supplier) {
    passwordSuppliers.put(publicKey, supplier);
  }

  public void removePasswordSupplier(final BLSPublicKey publicKey) {
    passwordSuppliers.remove(publicKey);
  }
}
