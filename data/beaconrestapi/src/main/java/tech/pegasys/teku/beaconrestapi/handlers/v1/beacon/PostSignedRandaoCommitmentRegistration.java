package tech.pegasys.teku.beaconrestapi.handlers.v1.beacon;

import static jakarta.servlet.http.HttpServletResponse.SC_OK;
import static tech.pegasys.teku.infrastructure.http.HttpStatusCodes.SC_BAD_REQUEST;
import static tech.pegasys.teku.infrastructure.json.types.CoreTypes.HTTP_ERROR_RESPONSE_TYPE;

import com.fasterxml.jackson.core.JsonProcessingException;
import tech.pegasys.teku.api.ChainDataProvider;
import tech.pegasys.teku.api.NodeDataProvider;
import tech.pegasys.teku.infrastructure.async.SafeFuture;
import tech.pegasys.teku.infrastructure.http.RestApiConstants;
import tech.pegasys.teku.infrastructure.restapi.endpoints.AsyncApiResponse;
import tech.pegasys.teku.infrastructure.restapi.endpoints.EndpointMetadata;
import tech.pegasys.teku.infrastructure.restapi.endpoints.RestApiEndpoint;
import tech.pegasys.teku.infrastructure.restapi.endpoints.RestApiRequest;
import tech.pegasys.teku.spec.datastructures.operations.SignedRandaoCommitmentRegistration;

public class PostSignedRandaoCommitmentRegistration extends RestApiEndpoint {
    private final NodeDataProvider nodeDataProvider;
    private final ChainDataProvider chainDataProvider;

    public PostSignedRandaoCommitmentRegistration(
            final NodeDataProvider nodeDataProvider,
            final ChainDataProvider chainDataProvider) {
        super(
                EndpointMetadata.post("/eth/v1/beacon/pool/randao_registrations")
                        .operationId("submitSignedRandaoCommitmentRegistration")
                        .summary("Submit Signed RANDAO Commitment Registration")
                        .description("Submit signed RANDAO commitment registration to the beacon node pool.")
                        .tags(RestApiConstants.TAG_BEACON)
                        .requestBodyType(SignedRandaoCommitmentRegistration.SSZ_SCHEMA.getJsonTypeDefinition())
                        .response(SC_OK, "Success")
                        .response(SC_BAD_REQUEST, "Invalid request body or signature", HTTP_ERROR_RESPONSE_TYPE)
                        .build());
        this.nodeDataProvider = nodeDataProvider;
        this.chainDataProvider = chainDataProvider;
    }

    @Override
    public void handleRequest(final RestApiRequest request) throws JsonProcessingException {
        final SignedRandaoCommitmentRegistration registration = request.getRequestBody();

        final SafeFuture<Void> response = nodeDataProvider.submitSignedRandaoCommitmentRegistration(registration);

        request.respondAsync(
                response
                        .thenApply(unused -> AsyncApiResponse.respondOk(null))
                        .exceptionally(error -> AsyncApiResponse.respondWithError(SC_BAD_REQUEST, error.getMessage())));
    }
}