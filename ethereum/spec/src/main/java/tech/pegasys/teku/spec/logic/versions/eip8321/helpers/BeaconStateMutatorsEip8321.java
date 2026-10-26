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

package tech.pegasys.teku.spec.logic.versions.eip8321.helpers;

import static com.google.common.base.Preconditions.checkArgument;

import org.apache.tuweni.bytes.Bytes32;
import tech.pegasys.teku.bls.BLSPublicKey;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszBytes32;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.config.SpecConfigGloas;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.MutableBeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.MutableBeaconStateEip8321;
import tech.pegasys.teku.spec.logic.common.helpers.BeaconStateMutators;
import tech.pegasys.teku.spec.logic.versions.gloas.helpers.BeaconStateAccessorsGloas;
import tech.pegasys.teku.spec.logic.versions.gloas.helpers.BeaconStateMutatorsGloas;
import tech.pegasys.teku.spec.logic.versions.heze.helpers.MiscHelpersHeze;
import tech.pegasys.teku.spec.schemas.SchemaDefinitionsGloas;

public class BeaconStateMutatorsEip8321 extends BeaconStateMutatorsGloas {

  public static BeaconStateMutatorsEip8321 required(final BeaconStateMutators beaconStateMutators) {
    checkArgument(
        beaconStateMutators instanceof BeaconStateMutatorsEip8321,
        "Expected %s but it was %s",
        BeaconStateMutatorsEip8321.class,
        beaconStateMutators.getClass());
    return (BeaconStateMutatorsEip8321) beaconStateMutators;
  }

  public BeaconStateMutatorsEip8321(
      final SpecConfigGloas specConfig,
      final MiscHelpersHeze miscHelpers,
      final BeaconStateAccessorsGloas beaconStateAccessors,
      final SchemaDefinitionsGloas schemaDefinitions) {
    super(specConfig, miscHelpers, beaconStateAccessors, schemaDefinitions);
  }

  @Override
  public void addValidatorToRegistry(
      final MutableBeaconState state,
      final BLSPublicKey pubkey,
      final Bytes32 withdrawalCredentials,
      final UInt64 amount) {
    super.addValidatorToRegistry(state, pubkey, withdrawalCredentials, amount);
    final MutableBeaconStateEip8321 stateEip8321 = MutableBeaconStateEip8321.required(state);
    stateEip8321.getRandaoCommitments().append(SszBytes32.of(Bytes32.ZERO));
  }
}
