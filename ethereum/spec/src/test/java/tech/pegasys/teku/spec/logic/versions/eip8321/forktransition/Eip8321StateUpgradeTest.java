package tech.pegasys.teku.spec.logic.versions.eip8321.forktransition;

import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.Spec;
import tech.pegasys.teku.spec.SpecMilestone;
import tech.pegasys.teku.spec.SpecVersion;
import tech.pegasys.teku.spec.TestSpecFactory;
import tech.pegasys.teku.spec.config.SpecConfigEip8321;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.eip8321.BeaconStateEip8321;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.gloas.BeaconStateGloas;
import tech.pegasys.teku.spec.logic.versions.gloas.helpers.BeaconStateAccessorsGloas;
import tech.pegasys.teku.spec.schemas.SchemaDefinitionsEip8321;
import tech.pegasys.teku.spec.util.DataStructureUtil;

import static org.assertj.core.api.Assertions.assertThat;

class Eip8321StateUpgradeTest {
    private static final UInt64 EIP8321_EPOCH = UInt64.valueOf(2);

    private final Spec spec = TestSpecFactory.createMinimalWithEip8321ForkEpoch(EIP8321_EPOCH);
    private final DataStructureUtil dataStructureUtil = new DataStructureUtil(spec);

    @Test
    void shouldInitializeRandaoCommitmentsForExistingValidators() {
        final BeaconStateGloas preState =
            BeaconStateGloas.required(
                dataStructureUtil
                    .stateBuilder(SpecMilestone.EIP8321, 3, 0)
                    .setSlotToStartOfEpoch(EIP8321_EPOCH)
                    .build());
        final BeaconStateEip8321 postState = createStateUpgrade().upgrade(preState);

        assertThat(postState.getFork().getPreviousVersion())
            .isEqualTo(preState.getFork().getCurrentVersion());
        assertThat(postState.getFork().getCurrentVersion())
            .isEqualTo(
                SpecConfigEip8321.required(spec.atEpoch(EIP8321_EPOCH).getConfig())
                    .getEip8321ForkVersion());
        assertThat(postState.getFork().getEpoch()).isEqualTo(EIP8321_EPOCH);

        assertThat(postState.getRandaoCommitments())
            .hasSize(preState.getValidators().size());
        assertThat(postState.getRandaoCommitments())
            .allSatisfy(commitment -> assertThat(commitment.get()).isEqualTo(Bytes32.ZERO));

        assertThat(postState.getPendingRandaoCommitments()).isEmpty();

        assertThat(postState.getValidators()).isEqualTo(preState.getValidators());
        assertThat(postState.getBalances()).isEqualTo(preState.getBalances());
        assertThat(postState.getProposerLookahead()).isEqualTo(preState.getProposerLookahead());
    }

    private Eip8321StateUpgrade createStateUpgrade() {
        final SpecVersion eip8321Spec = spec.atEpoch(EIP8321_EPOCH);

        return new Eip8321StateUpgrade(
            SpecConfigEip8321.required(eip8321Spec.getConfig()),
            SchemaDefinitionsEip8321.required(eip8321Spec.getSchemaDefinitions()),
            BeaconStateAccessorsGloas.required(eip8321Spec.beaconStateAccessors())
        );
    }
}
