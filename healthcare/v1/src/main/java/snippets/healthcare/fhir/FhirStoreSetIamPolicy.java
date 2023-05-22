/*
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package snippets.healthcare.fhir;

// [START healthcare_fhir_store_set_iam_policy]
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.healthcare.v1.CloudHealthcare;
import com.google.api.services.healthcare.v1.CloudHealthcare.Projects.Locations.Datasets.FhirStores;
import com.google.api.services.healthcare.v1.CloudHealthcareScopes;
import com.google.api.services.healthcare.v1.model.Binding;
import com.google.api.services.healthcare.v1.model.Policy;
import com.google.api.services.healthcare.v1.model.SetIamPolicyRequest;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

public class FhirStoreSetIamPolicy {
  private static final String FHIR_NAME = "projects/%s/locations/%s/datasets/%s/fhirStores/%s";
  private static final JsonFactory JSON_FACTORY = new GsonFactory();
  private static final NetHttpTransport HTTP_TRANSPORT = new NetHttpTransport();

  public static void fhirStoreSetIamPolicy(String fhirStoreName) throws IOException {
    // String fhirStoreName =
    //    String.format(
    //        FHIR_NAME, "your-project-id", "your-region-id", "your-dataset-id", "your-fhir-id");

    // Initialize the client, which will be used to interact with the service.
    CloudHealthcare client = createClient();

    // Configure the IAMPolicy to apply to the store.
    // For more information on understanding IAM roles, see the following:
    // https://cloud.google.com/iam/docs/understanding-roles
    Binding binding =
        new Binding()
            .setRole("roles/healthcare.fhirResourceReader")
            .setMembers(Arrays.asList("domain:google.com"));
    Policy policy = new Policy().setBindings(Arrays.asList(binding));
    SetIamPolicyRequest policyRequest = new SetIamPolicyRequest().setPolicy(policy);

    // Create request and configure any parameters.
    FhirStores.SetIamPolicy request =
        client
            .projects()
            .locations()
            .datasets()
            .fhirStores()
            .setIamPolicy(fhirStoreName, policyRequest);

    // Execute the request and process the results.
    Policy updatedPolicy = request.execute();
    System.out.println("FHIR policy has been updated: " + updatedPolicy.toPrettyString());
  }

  private static CloudHealthcare createClient() throws IOException {
    // Use Application Default Credentials (ADC) to authenticate the requests
    // For more information see https://cloud.google.com/docs/authentication/production
    GoogleCredentials credential =
        GoogleCredentials.getApplicationDefault()
            .createScoped(Collections.singleton(CloudHealthcareScopes.CLOUD_PLATFORM));

    // Create a HttpRequestInitializer, which will provide a baseline configuration to all requests.
    HttpRequestInitializer requestInitializer =
        request -> {
          new HttpCredentialsAdapter(credential).initialize(request);
          request.setConnectTimeout(60000); // 1 minute connect timeout
          request.setReadTimeout(60000); // 1 minute read timeout
        };

    // Build the client for interacting with the service.
    return new CloudHealthcare.Builder(HTTP_TRANSPORT, JSON_FACTORY, requestInitializer)
        .setApplicationName("your-application-name")
        .build();
  }
}
// [END healthcare_fhir_store_set_iam_policy]
