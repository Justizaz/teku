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

package tech.pegasys.teku.validator.eventadapter;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import java.util.Optional;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;
import tech.pegasys.teku.infrastructure.events.EventChannels;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.Spec;
import tech.pegasys.teku.spec.TestSpecFactory;
import tech.pegasys.teku.spec.util.DataStructureUtil;
import tech.pegasys.teku.validator.api.ValidatorTimingChannel;
import tech.pegasys.teku.validator.beaconnode.BeaconChainEventAdapter;

class IndependentTimerEventChannelEventAdapterTest {

  private static final UInt64 SLOT = UInt64.valueOf(134);

  private final ValidatorTimingChannel validatorTimingChannel = mock(ValidatorTimingChannel.class);
  private final DataStructureUtil dataStructureUtil =
      new DataStructureUtil(TestSpecFactory.createDefault());
  private final Bytes32 blockRoot = dataStructureUtil.randomBytes32();
  private final Bytes32 previousDutyDependentRoot = dataStructureUtil.randomBytes32();
  private final Bytes32 currentDutyDependentRoot = dataStructureUtil.randomBytes32();

  @Test
  void chainHeadUpdated_shouldTriggerAttestationCreationBeforeHeze() {
    notifyChainHeadUpdated(createAdapter(true, TestSpecFactory.createMinimalGloas()));

    verify(validatorTimingChannel)
        .onHeadUpdate(SLOT, previousDutyDependentRoot, currentDutyDependentRoot, blockRoot);
    verify(validatorTimingChannel).onAttestationCreationDue(SLOT);
    verifyNoMoreInteractions(validatorTimingChannel);
  }

  @Test
  void chainHeadUpdated_shouldTriggerInclusionListCreationFromHeze() {
    notifyChainHeadUpdated(createAdapter(true, TestSpecFactory.createMinimalHeze()));

    verify(validatorTimingChannel)
        .onHeadUpdate(SLOT, previousDutyDependentRoot, currentDutyDependentRoot, blockRoot);
    verify(validatorTimingChannel).onAttestationCreationDue(SLOT);
    verify(validatorTimingChannel).onInclusionListCreationDue(SLOT);
    verifyNoMoreInteractions(validatorTimingChannel);
  }

  @Test
  void chainHeadUpdated_shouldNotTriggerEarlyDutiesWhenDisabled() {
    notifyChainHeadUpdated(createAdapter(false, TestSpecFactory.createMinimalHeze()));

    verify(validatorTimingChannel)
        .onHeadUpdate(SLOT, previousDutyDependentRoot, currentDutyDependentRoot, blockRoot);
    verifyNoMoreInteractions(validatorTimingChannel);
  }

  private IndependentTimerEventChannelEventAdapter createAdapter(
      final boolean generateEarlyAttestations, final Spec spec) {
    return new IndependentTimerEventChannelEventAdapter(
        mock(EventChannels.class),
        generateEarlyAttestations,
        mock(BeaconChainEventAdapter.class),
        validatorTimingChannel,
        spec);
  }

  private void notifyChainHeadUpdated(final IndependentTimerEventChannelEventAdapter adapter) {
    adapter.chainHeadUpdated(
        SLOT,
        dataStructureUtil.randomBytes32(),
        blockRoot,
        false,
        false,
        previousDutyDependentRoot,
        currentDutyDependentRoot,
        Optional.empty(),
        Optional.empty());
  }
}
