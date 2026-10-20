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

package tech.pegasys.teku.spec.datastructures.operations;

import org.apache.tuweni.bytes.Bytes32;
import tech.pegasys.teku.infrastructure.ssz.containers.Container3;
import tech.pegasys.teku.infrastructure.ssz.containers.ContainerSchema3;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszBytes32;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszUInt64;
import tech.pegasys.teku.infrastructure.ssz.schema.SszPrimitiveSchemas;
import tech.pegasys.teku.infrastructure.ssz.tree.TreeNode;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;

public class PendingRandaoCommitment
        extends Container3<PendingRandaoCommitment, SszUInt64, SszBytes32, SszUInt64> {
    public static final PendingRandaoCommitmentSchema SSZ_SCHEMA =
            new PendingRandaoCommitmentSchema();

    public PendingRandaoCommitment(
            final UInt64 validatorIndex, final Bytes32 commitment, final UInt64 activationEpoch) {
        super(
                SSZ_SCHEMA,
                SszUInt64.of(validatorIndex),
                SszBytes32.of(commitment),
                SszUInt64.of(activationEpoch));
    }

    protected PendingRandaoCommitment(
            final PendingRandaoCommitmentSchema schema, final TreeNode backingNode) {
        super(schema, backingNode);
    }

    public UInt64 getValidatorIndex() {
        return getField0().get();
    }

    public Bytes32 getCommitment() {
        return getField1().get();
    }

    public UInt64 getActivationEpoch() {
        return getField2().get();
    }

    public static class PendingRandaoCommitmentSchema
            extends ContainerSchema3<PendingRandaoCommitment, SszUInt64, SszBytes32, SszUInt64> {
        public PendingRandaoCommitmentSchema() {
            super(
                    "PendingRandaoCommitment",
                    namedSchema("validator_index", SszPrimitiveSchemas.UINT64_SCHEMA),
                    namedSchema("commitment", SszPrimitiveSchemas.BYTES32_SCHEMA),
                    namedSchema("activation_epoch", SszPrimitiveSchemas.UINT64_SCHEMA));
        }

        @Override
        public PendingRandaoCommitment createFromBackingNode(final TreeNode backingNode) {
            return new PendingRandaoCommitment(this, backingNode);
        }
    }
}