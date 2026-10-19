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

package tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321;

import java.util.ArrayList;
import java.util.List;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszBytes32;
import tech.pegasys.teku.infrastructure.ssz.schema.SszListSchema;
import tech.pegasys.teku.infrastructure.ssz.schema.SszPrimitiveSchemas;
import tech.pegasys.teku.infrastructure.ssz.tree.TreeNode;
import tech.pegasys.teku.spec.config.SpecConfigEip8321;
import tech.pegasys.teku.spec.datastructures.operations.PendingRandaoCommitment;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.common.AbstractBeaconStateSchema;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.electra.BeaconStateSchemaElectra;

public class BeaconStateSchemaEip8321Impl
        extends AbstractBeaconStateSchema<BeaconStateEip8321, MutableBeaconStateEip8321>
        implements BeaconStateSchemaEip8321<BeaconStateEip8321> {

    private BeaconStateSchemaEip8321Impl(final List<NamedSchema<?>> fields) {
        super("BeaconStateEip8321", fields);
    }

    public static BeaconStateSchemaEip8321Impl create(final SpecConfigEip8321 specConfig) {
        final List<NamedSchema<?>> fields =
                new ArrayList<>(BeaconStateSchemaElectra.getElectraFields(specConfig));
        fields.add(
                namedSchema(
                        "randao_commitments",
                        SszListSchema.create(
                                SszPrimitiveSchemas.BYTES32_SCHEMA,
                                specConfig.getMaxRandaoCommitmentRegistrations())));
        fields.add(
                namedSchema(
                        "pending_randao_commitments",
                        SszListSchema.create(
                                PendingRandaoCommitment.SSZ_SCHEMA,
                                specConfig.getMaxRandaoCommitmentRegistrations())));
        return new BeaconStateSchemaEip8321Impl(fields);
    }

    @Override
    public BeaconStateEip8321 createFromBackingNode(final TreeNode node) {
        return new BeaconStateEip8321Impl(this, node);
    }

    @Override
    public MutableBeaconStateEip8321 createBuilder() {
        return new MutableBeaconStateEip8321Impl((BeaconStateEip8321Impl) createEmpty());
    }

    @Override
    public BeaconStateEip8321 createEmpty() {
        return new BeaconStateEip8321Impl(this);
    }

    @SuppressWarnings("unchecked")
    @Override
    public SszListSchema<SszBytes32, ?> getRandaoCommitmentsSchema() {
        final int index = getFieldIndex("randao_commitments");
        return (SszListSchema<SszBytes32, ?>) getChildSchema(index);
    }

    @SuppressWarnings("unchecked")
    @Override
    public SszListSchema<PendingRandaoCommitment, ?> getPendingRandaoCommitmentsSchema() {
        final int index = getFieldIndex("pending_randao_commitments");
        return (SszListSchema<PendingRandaoCommitment, ?>) getChildSchema(index);
    }
}