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

package tech.pegasys.teku.beaconrestapi.handlers.v1.beacon;

import static tech.pegasys.teku.infrastructure.http.HttpStatusCodes.SC_BAD_REQUEST;
import static tech.pegasys.teku.infrastructure.http.HttpStatusCodes.SC_OK;
import static tech.pegasys.teku.infrastructure.http.RestApiConstants.TAG_BEACON;

import com.fasterxml.jackson.core.JsonProcessingException;
import tech.pegasys.teku.api.DataProvider;
import tech.pegasys.teku.api.NodeDataProvider;
import tech.pegasys.teku.infrastructure.async.SafeFuture;
import tech.pegasys.teku.infrastructure.restapi.endpoints.AsyncApiResponse;
import tech.pegasys.teku.infrastructure.restapi.endpoints.EndpointMetadata;
import tech.pegasys.teku.infrastructure.restapi.endpoints.RestApiEndpoint;
import tech.pegasys.teku.infrastructure.restapi.endpoints.RestApiRequest;
import tech.pegasys.teku.spec.datastructures.operations.SignedRandaoCommitmentRegistration;
import tech.pegasys.teku.statetransition.validation.InternalValidationResult;

public class PostSignedRandaoCommitmentRegistration extends RestApiEndpoint {
    public static final String ROUTE = "/eth/v1/beacon/pool/randao_commitments";
    private final NodeDataProvider nodeDataProvider;

    public PostSignedRandaoCommitmentRegistration(final NodeDataProvider provider) {
        super(createEndpointMetadata());
        this.nodeDataProvider = provider;
    }

    public PostSignedRandaoCommitmentRegistration(final DataProvider dataProvider) {
        this(dataProvider.getNodeDataProvider());
    }

    private static EndpointMetadata createEndpointMetadata() {
        return EndpointMetadata.post(ROUTE)
                .operationId("submitSignedRandaoCommitmentRegistration")
                .summary("Submit SignedRandaoCommitmentRegistration object to node's pool")
                .description(
                        "Submits SignedRandaoCommitmentRegistration object to node's pool and if passes validation node MUST broadcast it to network.")
                .tags(TAG_BEACON)
                .requestBodyType(SignedRandaoCommitmentRegistration.SSZ_SCHEMA.getJsonTypeDefinition())
                .response(SC_OK, "Randao commitment registration is stored in node and broadcast to network")
                .response(SC_BAD_REQUEST, "Invalid randao commitment registration")
                .build();
    }

    @Override
    public void handleRequest(final RestApiRequest request) throws JsonProcessingException {
        final SignedRandaoCommitmentRegistration registration = request.getRequestBody();
        final SafeFuture<InternalValidationResult> future =
                nodeDataProvider.submitSignedRandaoCommitmentRegistration(registration);

        request.respondAsync(
                future.thenApply(
                        result -> {
                            if (result.isAccept()) {
                                return AsyncApiResponse.respondWithCode(SC_OK);
                            }
                            return AsyncApiResponse.respondWithError(
                                    SC_BAD_REQUEST,
                                    result.getDescription().orElse("Invalid randao commitment registration"));
                        }));
    }
}