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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static tech.pegasys.teku.infrastructure.http.HttpStatusCodes.SC_OK;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.pegasys.teku.beaconrestapi.AbstractMigratedBeaconHandlerTest;
import tech.pegasys.teku.infrastructure.async.SafeFuture;
import tech.pegasys.teku.spec.datastructures.operations.RandaoCommitmentRegistration;
import tech.pegasys.teku.spec.datastructures.operations.SignedRandaoCommitmentRegistration;
import tech.pegasys.teku.statetransition.validation.InternalValidationResult;

public class PostSignedRandaoCommitmentRegistrationTest extends AbstractMigratedBeaconHandlerTest {

    @BeforeEach
    public void setup() {
        setHandler(new PostSignedRandaoCommitmentRegistration(nodeDataProvider));
    }

    @Test
    void shouldBeAbleToSubmitRandaoCommitmentRegistration() throws Exception {
        final SignedRandaoCommitmentRegistration registration =
                new SignedRandaoCommitmentRegistration(
                        new RandaoCommitmentRegistration(
                                dataStructureUtil.randomUInt64(),
                                dataStructureUtil.randomBytes32()),
                        dataStructureUtil.randomSignature());

        request.setRequestBody(registration);
        when(nodeDataProvider.submitSignedRandaoCommitmentRegistration(registration))
                .thenReturn(SafeFuture.completedFuture(InternalValidationResult.ACCEPT));

        handler.handleRequest(request);

        assertThat(request.getResponseCode()).isEqualTo(SC_OK);
        assertThat(request.getResponseBody()).isNull();
    }
}