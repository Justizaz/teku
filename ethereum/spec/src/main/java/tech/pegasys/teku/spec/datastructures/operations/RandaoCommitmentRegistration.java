package tech.pegasys.teku.spec.datastructures.operations;

import org.apache.tuweni.bytes.Bytes32;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;

/**
 * EIP-8321: Hash-Chain RANDAO Commitment Registration
 */
public record RandaoCommitmentRegistration(
        UInt64 validatorIndex,
        Bytes32 commitment,
        UInt64 sequenceNumber
) {
    // Pradinė struktūra EIP-8321 užduočiai
}