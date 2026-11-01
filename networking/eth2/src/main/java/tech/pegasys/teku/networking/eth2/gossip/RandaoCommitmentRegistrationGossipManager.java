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

package tech.pegasys.teku.networking.eth2.gossip;

import tech.pegasys.teku.infrastructure.async.AsyncRunner;
import tech.pegasys.teku.infrastructure.bytes.Bytes4;
import tech.pegasys.teku.networking.eth2.gossip.encoding.GossipEncoding;
import tech.pegasys.teku.networking.eth2.gossip.topics.GossipTopicName;
import tech.pegasys.teku.networking.eth2.gossip.topics.OperationProcessor;
import tech.pegasys.teku.networking.p2p.gossip.GossipNetwork;
import tech.pegasys.teku.spec.config.NetworkingSpecConfig;
import tech.pegasys.teku.spec.datastructures.operations.SignedRandaoCommitmentRegistration;
import tech.pegasys.teku.spec.datastructures.state.ForkInfo;
import tech.pegasys.teku.statetransition.util.DebugDataDumper;
import tech.pegasys.teku.storage.client.RecentChainData;

import java.util.Optional;

public class RandaoCommitmentRegistrationGossipManager
    extends AbstractGossipManager<SignedRandaoCommitmentRegistration> {

  public RandaoCommitmentRegistrationGossipManager(
      final RecentChainData recentChainData,
      final AsyncRunner asyncRunner,
      final GossipNetwork gossipNetwork,
      final GossipEncoding gossipEncoding,
      final ForkInfo forkInfo,
      final Bytes4 forkDigest,
      final OperationProcessor<SignedRandaoCommitmentRegistration> processor,
      final NetworkingSpecConfig networkingConfig,
      final DebugDataDumper debugDataDumper) {
    super(
        recentChainData,
        GossipTopicName.RANDAO_COMMITMENT_REGISTRATION,
        asyncRunner,
        gossipNetwork,
        gossipEncoding,
        forkInfo,
        forkDigest,
        processor,
        SignedRandaoCommitmentRegistration.SSZ_SCHEMA,
        message -> Optional.empty(),
        // Registrations have no slot, so they are validated against the fork
        // representedd by the topic on which they arrived.
        message -> forkInfo.getFork().getEpoch(),
        networkingConfig,
        GossipFailureLogger.createSuppressing(GossipTopicName.RANDAO_COMMITMENT_REGISTRATION.toString()),
        debugDataDumper);
  }

  public void publish(final SignedRandaoCommitmentRegistration message) {
    publishMessage(message);
  }
}
