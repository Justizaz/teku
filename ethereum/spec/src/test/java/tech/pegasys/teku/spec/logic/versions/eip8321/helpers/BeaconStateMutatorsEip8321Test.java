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

import static org.assertj.core.api.Assertions.assertThat;

import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.pegasys.teku.bls.BLSPublicKey;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.Spec;
import tech.pegasys.teku.spec.TestSpecFactory;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.BeaconStateEip8321;
import tech.pegasys.teku.spec.util.DataStructureUtil;

class BeaconStateMutatorsEip8321Test {

  private final Spec spec = TestSpecFactory.createMinimalEip8321();
  private final DataStructureUtil dataStructureUtil = new DataStructureUtil(spec);

  private BeaconStateMutatorsEip8321 beaconStateMutators;

  @BeforeEach
  void setUp() {
    beaconStateMutators =
        BeaconStateMutatorsEip8321.required(spec.getGenesisSpec().beaconStateMutators());
    assertThat(beaconStateMutators).isNotNull();
  }

  @Test
  void addValidatorToRegistry_shouldAppendZeroCommitment() {
    final Spec spec = TestSpecFactory.createMinimalHeze();
    final DataStructureUtil hezeUtil = new DataStructureUtil(spec);
    final BeaconState baseState = hezeUtil.randomBeaconStateWithActiveValidators(16, UInt64.ZERO);

    final BeaconStateEip8321 preState =
        (BeaconStateEip8321)
            this.spec.getGenesisSpec().getStateUpgrade().orElseThrow().upgrade(baseState);

    final int initialValidatorCount = preState.getValidators().size();
    final int initialCommitmentCount = preState.getRandaoCommitments().size();
    assertThat(initialCommitmentCount).isEqualTo(initialValidatorCount);

    final BLSPublicKey newPubKey = dataStructureUtil.randomPublicKey();
    final Bytes32 withdrawalCredentials = dataStructureUtil.randomBytes32();
    final UInt64 amount = UInt64.THIRTY_TWO_ETH;

    final BeaconStateEip8321 postState =
        preState.updatedEip8321(
            mutableState ->
                beaconStateMutators.addValidatorToRegistry(
                    mutableState, newPubKey, withdrawalCredentials, amount));

    assertThat(postState.getValidators().size()).isEqualTo(initialValidatorCount + 1);
    assertThat(postState.getRandaoCommitments().size()).isEqualTo(initialCommitmentCount + 1);
    assertThat(postState.getRandaoCommitments().get(initialCommitmentCount).get())
        .isEqualTo(Bytes32.ZERO);
    assertThat(postState.getValidators().get(initialValidatorCount).getPublicKey())
        .isEqualTo(newPubKey);
    assertThat(postState.getBalances().getElement(initialValidatorCount)).isEqualTo(amount);
  }

  @Test
  void addMultipleValidatorsToRegistry_shouldAppendZeroCommitmentsConsistently() {
    final Spec spec = TestSpecFactory.createMinimalHeze();
    final DataStructureUtil hezeUtil = new DataStructureUtil(spec);
    final BeaconState baseState = hezeUtil.randomBeaconStateWithActiveValidators(8, UInt64.ZERO);

    final BeaconStateEip8321 preState =
        (BeaconStateEip8321)
            this.spec.getGenesisSpec().getStateUpgrade().orElseThrow().upgrade(baseState);

    final int initialValidatorCount = preState.getValidators().size();

    final BeaconStateEip8321 postState =
        preState.updatedEip8321(
            mutableState -> {
              for (int i = 0; i < 5; i++) {
                beaconStateMutators.addValidatorToRegistry(
                    mutableState,
                    dataStructureUtil.randomPublicKey(),
                    dataStructureUtil.randomBytes32(),
                    UInt64.THIRTY_TWO_ETH);
              }
            });

    assertThat(postState.getValidators().size()).isEqualTo(initialValidatorCount + 5);
    assertThat(postState.getRandaoCommitments().size()).isEqualTo(initialValidatorCount + 5);
    for (int i = 0; i < 5; i++) {
      assertThat(postState.getRandaoCommitments().get(initialValidatorCount + i).get())
          .isEqualTo(Bytes32.ZERO);
    }
  }
}
