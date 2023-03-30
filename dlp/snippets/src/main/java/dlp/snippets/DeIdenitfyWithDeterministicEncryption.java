/*
 * Copyright 2023 Google LLC
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

package dlp.snippets;

// [START dlp_deidentify_deterministic]

import com.google.cloud.dlp.v2.DlpServiceClient;
import com.google.privacy.dlp.v2.*;
import com.google.protobuf.ByteString;
import org.apache.commons.codec.binary.Base64;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

public class DeIdenitfyWithDeterministicEncryption {

  public static void main(String[] args) throws Exception {
    // TODO(developer): Replace these variables before running the sample.
    String projectId = "your-project-id";
    String textToDeIdentify = "My SSN is 372819127";
    String wrappedKey =
        "YOUR_ENCRYPTED_AES_256_KEY";
    String kmsKeyName =
            "projects/YOUR_PROJECT/"
                    + "locations/YOUR_KEYRING_REGION/"
                    + "keyRings/YOUR_KEYRING_NAME/"
                    + "cryptoKeys/YOUR_KEY_NAME";
    deIdentifyWithDeterministicEncryption(projectId, textToDeIdentify, wrappedKey, kmsKeyName);
  }

  public static void deIdentifyWithDeterministicEncryption(
      String projectId, String textToDeIdentify, String wrappedKey, String key) throws IOException {
    // Initialize client that will be used to send requests. This client only needs to be created
    // once, and can be reused for multiple requests. After completing all of your requests, call
    // the "close" method on the client to safely clean up any remaining background resources.
    try (DlpServiceClient dlp = DlpServiceClient.create()) {
      // Specify what content you want the service to DeIdentify
      ContentItem contentItem = ContentItem.newBuilder().setValue(textToDeIdentify).build();

      // Specify the type of info the inspection will look for.
      // See https://cloud.google.com/dlp/docs/infotypes-reference for complete list of info types
      InfoType infoType = InfoType.newBuilder().setName("US_SOCIAL_SECURITY_NUMBER").build();
      InspectConfig inspectConfig =
          InspectConfig.newBuilder().addAllInfoTypes(Collections.singletonList(infoType)).build();

      // Specify an encrypted AES-256 key and the name of the Cloud KMS key that encrypted it
      KmsWrappedCryptoKey unwrappedCryptoKey =
          KmsWrappedCryptoKey.newBuilder()
              .setWrappedKey(
                  ByteString.copyFrom(
                      Base64.decodeBase64(wrappedKey.getBytes(StandardCharsets.UTF_8))))
              .setCryptoKeyName(key)
              .build();
      CryptoKey cryptoKey = CryptoKey.newBuilder().setKmsWrapped(unwrappedCryptoKey).build();

      // Specify how the info from the inspection should be encrypted.
      InfoType surrogateInfoType = InfoType.newBuilder().setName("SSN_TOKEN").build();
      CryptoDeterministicConfig cryptoDeterministicConfig =
          CryptoDeterministicConfig.newBuilder()
              .setSurrogateInfoType(surrogateInfoType)
              .setCryptoKey(cryptoKey)
              .build();
      PrimitiveTransformation primitiveTransformation =
          PrimitiveTransformation.newBuilder()
              .setCryptoDeterministicConfig(cryptoDeterministicConfig)
              .build();
      InfoTypeTransformations.InfoTypeTransformation infoTypeTransformation =
          InfoTypeTransformations.InfoTypeTransformation.newBuilder()
              .setPrimitiveTransformation(primitiveTransformation)
              .build();
      InfoTypeTransformations transformations =
          InfoTypeTransformations.newBuilder().addTransformations(infoTypeTransformation).build();

      DeidentifyConfig deidentifyConfig =
          DeidentifyConfig.newBuilder().setInfoTypeTransformations(transformations).build();

      // Combine configurations into a request for the service.
      DeidentifyContentRequest request =
          DeidentifyContentRequest.newBuilder()
              .setParent(LocationName.of(projectId, "global").toString())
              .setItem(contentItem)
              .setInspectConfig(inspectConfig)
              .setDeidentifyConfig(deidentifyConfig)
              .build();

      // Send the request and receive response from the service
      DeidentifyContentResponse response = dlp.deidentifyContent(request);

      // Print the results
      System.out.println(
          "Text after format-preserving encryption: " + response.getItem().getValue());
    }
  }
}

// [END dlp_deidentify_deterministic]
