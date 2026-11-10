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

package tech.pegasys.teku.beaconrestapi.v1.beacon;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static tech.pegasys.teku.infrastructure.http.HttpStatusCodes.SC_BAD_REQUEST;
import static tech.pegasys.teku.infrastructure.http.HttpStatusCodes.SC_OK;

import java.io.IOException;
import okhttp3.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.pegasys.teku.beaconrestapi.AbstractDataBackedRestAPIIntegrationTest;
import tech.pegasys.teku.beaconrestapi.handlers.v1.beacon.PostSignedRandaoCommitmentRegistration;
import tech.pegasys.teku.infrastructure.async.SafeFuture;
import tech.pegasys.teku.infrastructure.json.JsonUtil;
import tech.pegasys.teku.spec.SpecMilestone;
import tech.pegasys.teku.spec.TestSpecFactory;
import tech.pegasys.teku.spec.datastructures.operations.SignedRandaoCommitmentRegistration;
import tech.pegasys.teku.spec.util.DataStructureUtil;
import tech.pegasys.teku.statetransition.validation.InternalValidationResult;

public class PostRandaoCommitmentsIntegrationTest extends AbstractDataBackedRestAPIIntegrationTest {

  private DataStructureUtil dataStructureUtil;

  @BeforeEach
  public void beforeEach() {
    spec = TestSpecFactory.createMinimalEip8321();
    dataStructureUtil = new DataStructureUtil(spec);
    startRestAPIAtGenesis(SpecMilestone.EIP8321);
  }

  @Test
  void postValidRandaoCommitmentRegistrationReturnsOk() throws IOException {
    final SignedRandaoCommitmentRegistration registration =
        dataStructureUtil.randomSignedRandaoCommitmentRegistration();

    when(randaoCommitmentRegistrationPool.addLocal(any()))
        .thenReturn(SafeFuture.completedFuture(InternalValidationResult.ACCEPT));

    final Response response =
        post(
            PostSignedRandaoCommitmentRegistration.ROUTE,
            JsonUtil.serialize(
                registration,
                SignedRandaoCommitmentRegistration.SSZ_SCHEMA.getJsonTypeDefinition()));

    assertThat(response.code()).isEqualTo(SC_OK);
    verify(randaoCommitmentRegistrationPool).addLocal(registration);
  }

  @Test
  void postInvalidRandaoCommitmentRegistrationReturnsBadRequest() throws IOException {
    final SignedRandaoCommitmentRegistration registration =
        dataStructureUtil.randomSignedRandaoCommitmentRegistration();

    when(randaoCommitmentRegistrationPool.addLocal(any()))
        .thenReturn(
            SafeFuture.completedFuture(
                InternalValidationResult.reject("Invalid commitment registration")));

    final Response response =
        post(
            PostSignedRandaoCommitmentRegistration.ROUTE,
            JsonUtil.serialize(
                registration,
                SignedRandaoCommitmentRegistration.SSZ_SCHEMA.getJsonTypeDefinition()));

    assertThat(response.code()).isEqualTo(SC_BAD_REQUEST);
    assertThat(response.body().string()).contains("Invalid commitment registration");
  }
}
