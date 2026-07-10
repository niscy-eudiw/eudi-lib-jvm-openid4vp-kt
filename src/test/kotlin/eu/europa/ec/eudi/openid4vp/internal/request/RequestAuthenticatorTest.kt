/*
 * Copyright (c) 2023-2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.openid4vp.internal.request

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.internal.JwsJson
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertThrows
import java.time.Clock
import kotlin.test.*

@DisplayName("In case of request is coming through HTTP")
class ClientAuthenticatorOverHTTPTest {

    @DisplayName("when handling a request")
    @Nested
    inner class ClientAuthenticatorCommonTest {

        private val cfg = OpenId4VPConfig(
            supportedClientIdPrefixes = listOf(
                SupportedClientIdPrefix.X509Hash({ _ -> true }),
            ),
            vpConfiguration = VPConfiguration(
                vpFormatsSupported = VpFormatsSupported(
                    VpFormatsSupported.SdJwtVc.HAIP,
                    VpFormatsSupported.MsoMdoc(
                        issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                        deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    ),
                ),
            ),
            clock = Clock.systemDefaultZone(),
        )
        private val clientAuthenticator = ClientAuthenticator(cfg)

        @Test
        fun `if client_id is missing, authentication fails`() = runTest {
            val request = UnvalidatedRequestObject(clientId = null)
            // TODO re-enable this
//            assertFailsWithError<RequestValidationError.MissingClientId> {
//                clientAuthenticator.authenticateClientOverHttp(request)
//            }
        }

        @Test
        fun `if 'origin' is used as a client id prefix, authentication fails`() = runTest {
            val request = UnvalidatedRequestObject(clientId = "origin:test_client_id")
            // TODO re-enable this
//            assertFailsWithError<RequestValidationError.InvalidClientIdPrefix> {
//                clientAuthenticator.authenticateClientOverHttp(request)
//            }
        }
    }
}

@DisplayName("In case of request is coming through DC API")
class RequestAuthenticatorOverDCApiTest {

    private val didAlgAndKey = randomKey()

    private val x509HashSupportedPrefix = SupportedClientIdPrefix.X509Hash({ _ -> true })

    private val cfg = OpenId4VPConfig(
        vpConfiguration = VPConfiguration(
            vpFormatsSupported = VpFormatsSupported(
                VpFormatsSupported.SdJwtVc.HAIP,
                VpFormatsSupported.MsoMdoc(
                    issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                ),
            ),
        ),
        supportedClientIdPrefixes = listOf(x509HashSupportedPrefix),
        signedRequestConfiguration = SignedRequestConfiguration(
            supportedAlgorithms = JWSAlgorithm.Family.EC.toList() - JWSAlgorithm.ES256K,
            supportedRequestUriMethods = SupportedRequestUriMethods.Default,
            multiSignedRequestsPolicy = MultiSignedRequestsPolicy.Expect(ClientIdPrefix.X509Hash),
        ),
    )

    @DisplayName("when handling a multi-signed request")
    @Nested
    inner class ClientAuthenticatorMultiSignedRequestsTest {

        private val clientAuthenticator = ClientAuthenticator(cfg)

        // TODO Re-enable this
//        @Test
//        fun `if expected scheme is found request client is properly authenticated`() = runTest {
//            val didAlgAndKey = randomKey()
//            val request = UnvalidatedRequestObject(
//                expectedOrigins = listOf("test_origin", "test_origin_alt"),
//            ).multiSigned(
//                listOf(verifierAttestationSigner(didAlgAndKey, cfg.clock)),
//            )
//            val (authenticateClient, _) = clientAuthenticator.authenticateClientOverDCApi(request)
//            assertIs<AuthenticatedClient.DecentralizedIdentifier>(authenticateClient)
//        }
//
//        @Test
//        fun `if request expected scheme is not found in request fail`() = runTest {
//            val didAlgAndKey = randomKey()
//            val request = UnvalidatedRequestObject(
//                expectedOrigins = listOf("test_origin", "test_origin_alt"),
//            ).multiSigned(
//                listOf(verifierAttestationSigner(didAlgAndKey, cfg.clock)),
//            )
//            assertFailsWithError<RequestValidationError.NoMatchingClientPrefixInMultiSignedRequest> {
//                clientAuthenticator.authenticateClientOverDCApi("test_origin", request)
//            }
//        }

        @Test
        fun `can create a multi-signed request`() = runTest {
            val originalClientId = WRP.Random.client.id

            // Create two signers with different keys
            val (alg1, key1) = randomKey()
            val (alg2, key2) = randomKey()

            val signer1 = SchemeSigner(alg1, key1) { keyID(originalClientId.toString()) }
            val signer2 = SchemeSigner(alg2, key2) { keyID(originalClientId.toString()) }

            // Create a request object with client ID and expected origins
            val clientId = "decentralized_identifier:$originalClientId"
            val request = UnvalidatedRequestObject(
                clientId = clientId,
                expectedOrigins = listOf("test_origin", "test_origin_alt"),
            ).multiSigned(listOf(signer1, signer2))

            // Verify that the request is a ReceivedRequest.Signed with a JwsJson.General
            assertIs<ReceivedRequest.MultiSigned>(request)
            assertIs<JwsJson.General>(request.jwsJson)

            // Verify that the JwsJson.General has two signatures
            val jwsJson = request.jwsJson
            assertEquals(2, jwsJson.signatures.size)

            // Verify that the signatures have the correct protected headers
            val signature1 = jwsJson.signatures[0]
            val signature2 = jwsJson.signatures[1]

            assertNotNull(signature1.protected)
            assertNotNull(signature2.protected)
        }
    }
}
//
// Support
//

fun randomKey(): Pair<JWSAlgorithm, ECKey> =
    JWSAlgorithm.ES256 to ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).generate()

private inline fun <reified E : AuthorizationRequestError> assertFailsWithError(block: () -> Unit): E {
    val exception = assertThrows<AuthorizationRequestException>(block)
    return assertIs<E>(exception.error)
}

private fun UnvalidatedRequestObject.signedWithAttestation(
    alg: JWSAlgorithm,
    key: JWK,
    attestation: SignedJWT,
): ReceivedRequest.Signed = signed(alg, key) {
    this.customParam("jwt", attestation.serialize())
}

private fun UnvalidatedRequestObject.signed(
    alg: JWSAlgorithm,
    key: JWK,
    headerCustomization: (JWSHeader.Builder).() -> Unit = {},
): ReceivedRequest.Signed {
    val header = with(JWSHeader.Builder(alg)) {
        type(JOSEObjectType(OpenId4VPSpec.AUTHORIZATION_REQUEST_OBJECT_TYPE))
        headerCustomization()
        build()
    }
    val claimsSet = toJWTClaimSet()
    val jwt = SignedJWT(header, claimsSet).apply {
        val signer = DefaultJWSSignerFactory().createJWSSigner(key, alg)
        sign(signer)
    }
    return ReceivedRequest.Signed(jwt)
}
