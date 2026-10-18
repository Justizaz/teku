package tech.pegasys.teku.spec.datastructures.operations;

import org.apache.tuweni.bytes.Bytes32;
import tech.pegasys.teku.bls.BLSSignature;
import tech.pegasys.teku.infrastructure.ssz.collections.SszByteVector;
import tech.pegasys.teku.infrastructure.ssz.containers.Container3;
import tech.pegasys.teku.infrastructure.ssz.containers.ContainerSchema3;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszBytes32;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszUInt64;
import tech.pegasys.teku.infrastructure.ssz.schema.SszPrimitiveSchemas;
import tech.pegasys.teku.infrastructure.ssz.schema.collections.SszByteVectorSchema;
import tech.pegasys.teku.infrastructure.ssz.tree.TreeNode;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;

public class RandaoCommitmentRegistration
        extends Container3<RandaoCommitmentRegistration, SszUInt64, SszBytes32, SszByteVector> {

    public static final RandaoCommitmentRegistrationSchema SSZ_SCHEMA =
            new RandaoCommitmentRegistrationSchema();

    public RandaoCommitmentRegistration(
            final UInt64 validatorIndex, final Bytes32 commitment, final BLSSignature signature) {
        super(
                SSZ_SCHEMA,
                SszUInt64.of(validatorIndex),
                SszBytes32.of(commitment),
                SSZ_SCHEMA.getFieldSchema2().sszDeserialize(signature.toSSZBytes()));
    }

    protected RandaoCommitmentRegistration(
            final RandaoCommitmentRegistrationSchema schema, final TreeNode backingNode) {
        super(schema, backingNode);
    }

    public UInt64 getValidatorIndex() {
        return getField0().get();
    }

    public Bytes32 getCommitment() {
        return getField1().get();
    }

    public BLSSignature getSignature() {
        return BLSSignature.fromSSZBytes(getField2().sszSerialize());
    }

    public static class RandaoCommitmentRegistrationSchema
            extends ContainerSchema3<RandaoCommitmentRegistration, SszUInt64, SszBytes32, SszByteVector> {

        public RandaoCommitmentRegistrationSchema() {
            super(
                    "RandaoCommitmentRegistration",
                    namedSchema("validator_index", SszPrimitiveSchemas.UINT64_SCHEMA),
                    namedSchema("commitment", SszPrimitiveSchemas.BYTES32_SCHEMA),
                    namedSchema("signature", SszByteVectorSchema.create(96)));
        }

        @Override
        public RandaoCommitmentRegistration createFromBackingNode(final TreeNode backingNode) {
            return new RandaoCommitmentRegistration(this, backingNode);
        }
    }
}