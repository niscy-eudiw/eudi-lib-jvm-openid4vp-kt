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
package eu.europa.ec.eudi.openid4vp.internal.response

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.dcql.*
import eu.europa.ec.eudi.openid4vp.dcql.ClaimPathElement.Claim
import eu.europa.ec.eudi.openid4vp.internal.request.ClientMetaDataValidator
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedClientMetaData
import eu.europa.ec.eudi.openid4vp.internal.request.ValidatedClientMetaData
import eu.europa.ec.eudi.openid4vp.internal.request.asHttpsURL
import eu.europa.ec.eudi.openid4vp.internal.response.DefaultDispatcherTest.Verifier.assertIsJwtEncryptedWithVerifiersPublicKey
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.util.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.*
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertDoesNotThrow
import java.net.URI
import java.time.Clock
import kotlin.test.*

@DisplayName("When dispatching OpenId4VP responses")
class DefaultDispatcherTest {

    //
    // Verifier settings
    //

    internal object Verifier {

        val CLIENT_ORIGINAL_ID = "https://client.example.org"

        val responseEncryptionKeyPair: ECKey = ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.ENCRYPTION)
            .algorithm(JWEAlgorithm.ECDH_ES)
            .keyID("123")
            .generate()

        val metaDataRequestingEncryptedResponse = UnvalidatedClientMetaData(
            jwks = JWKSet(responseEncryptionKeyPair).toJsonObject(true),
            responseEncryptionMethodsSupported = listOf(EncryptionMethod.A256GCM.name),
            vpFormatsSupported = VpFormatsSupported(
                sdJwtVc = VpFormatsSupported.SdJwtVc.HAIP,
                msoMdoc = VpFormatsSupported.MsoMdoc(
                    issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                ),
            ),
        )

        private fun JWKSet.toJsonObject(publicKeysOnly: Boolean = true): JsonObject =
            Json.parseToJsonElement(this.toString(publicKeysOnly)).jsonObject

        fun String.assertIsJwtEncryptedWithVerifiersPublicKey(): EncryptedJWT {
            val jwt = assertDoesNotThrow { EncryptedJWT.parse(this) }
            val rsaDecrypter = ECDHDecrypter(responseEncryptionKeyPair)
            jwt.decrypt(rsaDecrypter)
            return jwt
        }

        fun createOpenId4VPRequest(
            unvalidatedClientMetaData: UnvalidatedClientMetaData,
            responseMode: ResponseMode,
            state: String? = null,
        ): ResolvedRequestObject {
            val query = DCQL(
                credentials = Credentials(
                    CredentialQuery.sdJwtVc(
                        id = QueryId("query_for_identity"),
                        DCQLMetaSdJwtVcExtensions(listOf("identity_credential")),
                    ),
                ),
            )
            val clientMetadataValidated =
                ClientMetaDataValidator.validateClientMetaData(
                    unvalidatedClientMetaData,
                    responseMode,
                    query,
                    Wallet.config.responseEncryptionConfiguration,
                    Wallet.config.vpConfiguration.vpFormatsSupported,
                )

            return ResolvedRequestObject(
                query = query,
                responseEncryptionSpecification = clientMetadataValidated.responseEncryptionSpecification,
                vpFormatsSupported = VpFormatsSupported(
                    msoMdoc = VpFormatsSupported.MsoMdoc(
                        issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                        deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    ),
                ),
                client = WRP.Random.client,
                nonce = "0S6_WzA2Mj",
                responseMode = responseMode,
                state = state ?: genState(),
                transactionData = null,
                verifierInfo = null,
            )
        }
    }

    //
    // Wallet settings
    //

    private object Wallet {
        val config = OpenId4VPConfig(
            supportedClientIdPrefixes = listOf(SupportedClientIdPrefix.X509SanDns.NoValidation),
            responseEncryptionConfiguration = ResponseEncryptionConfiguration.Supported(
                supportedAlgorithms = listOf(Verifier.responseEncryptionKeyPair.algorithm as JWEAlgorithm),
                supportedMethods = listOf(EncryptionMethod.A256GCM),
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

        /**
         * Creates a [DispatcherOverHttp] that mocks the behavior of a Verifier, in case of posting
         * an authorization response (direct post, or direct post jwt response_mode).
         *
         * The verifier asserts that it receives an HTTP Post, which contains [FormDataContent], having
         * a parameter named `response`
         *
         * @param responseBodyRedirectUri redirect uri to be included in the generate response body
         * @param responseParameterAssertions assertions applicable to the content of the form parameter
         * `response`
         */
        fun createDispatcherWithVerifierAsserting(
            responseBodyRedirectUri: URI? = null,
            responseParameterAssertions: (String) -> Unit,
        ): DispatcherOverHttp {
            val mockEngine = MockEngine { request ->
                assertEquals(HttpMethod.Post, request.method)
                request.body.contentType?.let {
                    assertEquals("application/x-www-form-urlencoded", it.toString())
                }
                request.headers[HttpHeaders.ContentType]?.let {
                    assertEquals("application/x-www-form-urlencoded", it)
                }
                val body = assertIs<FormData>(request.body)
                val responseParameter = body.formData["response"] as String
                responseParameterAssertions(responseParameter)

                val response = buildJsonObject {
                    responseBodyRedirectUri?.let { put("redirect_uri", JsonPrimitive(it.toString())) }
                }.toString()

                respond(
                    response,
                    HttpStatusCode.OK,
                    headers { append(HttpHeaders.ContentType, ContentType.Application.Json) },
                )
            }

            val httpClient = createHttpClient(mockEngine).config {
                expectSuccess = true
                install(ContentNegotiation) {
                    json()
                }
            }

            return DefaultDispatcherOverHttp(httpClient)
        }
    }

    @Nested
    @DisplayName("... as an ecrypted direct post (direct_post.jwt)")
    inner class DirectPostJwtResponse {

        @Test
        fun `if response type direct_post jwt, JWE should be returned if only encryption info specified`() = runTest {
            val verifierRequest = Verifier.createOpenId4VPRequest(
                Verifier.metaDataRequestingEncryptedResponse,
                ResponseMode.DirectPostJwt("https://respond.here".asHttpsURL().getOrThrow()),
            )

            suspend fun test(
                verifiablePresentations: List<VerifiablePresentation>,
                redirectUri: URI? = null,
            ) {
                val vpTokenConsensus = Consensus.PositiveConsensus(
                    VerifiablePresentations(
                        mapOf(
                            QueryId("psId") to verifiablePresentations,
                        ),
                    ),
                )

                val dispatcher = Wallet.createDispatcherWithVerifierAsserting(redirectUri) { responseParam ->
                    val encryptedJwt = responseParam.assertIsJwtEncryptedWithVerifiersPublicKey()
                    assertEquals(Base64URL.encode(verifierRequest.nonce), encryptedJwt.header.agreementPartyVInfo)
                    assertEquals(Base64URL.encode("dummy_apu"), encryptedJwt.header.agreementPartyUInfo)

                    val jwtClaimSet = encryptedJwt.jwtClaimsSet
                    val vpTokenClaim = jwtClaimSet.vpTokenClaim()
                    assertEquals(vpTokenConsensus.verifiablePresentations.asJsonObject(), vpTokenClaim)
                }

                val outcome = dispatcher.dispatch(
                    verifierRequest,
                    vpTokenConsensus,
                    EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
                )
                val expectedOutcome = DispatchOutcome.VerifierResponse.Accepted(redirectUri)
                assertEquals(expectedOutcome, outcome)
            }

            test(
                listOf(VerifiablePresentation.Generic("dummy_vp_token")),
                redirectUri = null,
            )
            test(
                listOf(VerifiablePresentation.Generic("dummy_vp_token")),
                redirectUri = URI.create("https://redirect.here"),
            )
        }

        @Test
        fun `if response direct_post jwt with encryption required, negative consensus must be dispatched in response`() =
            runTest {
                val verifierRequest = Verifier.createOpenId4VPRequest(
                    Verifier.metaDataRequestingEncryptedResponse,
                    ResponseMode.DirectPostJwt("https://respond.here".asHttpsURL().getOrThrow()),
                )

                val negativeConsensus = Consensus.NegativeConsensus

                val dispatcher = Wallet.createDispatcherWithVerifierAsserting { responseParam ->
                    val encryptedJwt = responseParam.assertIsJwtEncryptedWithVerifiersPublicKey()
                    assertEquals(Base64URL.encode(verifierRequest.nonce), encryptedJwt.header.agreementPartyVInfo)
                    assertEquals(Base64URL.encode("dummy_apu"), encryptedJwt.header.agreementPartyUInfo)

                    val jwtClaimSet = encryptedJwt.jwtClaimsSet
                    val errorClam = jwtClaimSet.getStringClaim("error")
                    assertNotNull(errorClam)
                    assertEquals("access_denied", errorClam)
                }

                dispatcher.dispatch(
                    verifierRequest,
                    negativeConsensus,
                    EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
                )
            }

        @Test
        fun `support vp_token with multiple verifiable presentations`() = runTest {
            suspend fun test(verifiablePresentations: VerifiablePresentations, redirectUri: URI? = null) {
                val responseMode = ResponseMode.DirectPostJwt("https://respond.here".asHttpsURL().getOrThrow())
                val resolvedRequest =
                    Verifier.createOpenId4VPRequest(Verifier.metaDataRequestingEncryptedResponse, responseMode)
                val vpTokenConsensus = Consensus.PositiveConsensus(
                    verifiablePresentations = verifiablePresentations,
                )

                val dispatcher = Wallet.createDispatcherWithVerifierAsserting(redirectUri) { responseParam ->
                    val jwtClaimsSet = responseParam.assertIsJwtEncryptedWithVerifiersPublicKey().jwtClaimsSet
                    assertEquals(
                        vpTokenConsensus.verifiablePresentations.asJsonObject(),
                        jwtClaimsSet.vpTokenClaim(),
                    )
                }

                val expectedOutcome = DispatchOutcome.VerifierResponse.Accepted(redirectUri)
                val outcome = dispatcher.dispatch(
                    resolvedRequest,
                    vpTokenConsensus,
                    EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
                )
                assertEquals(expectedOutcome, outcome)
            }

            test(vpTokenWithMultipleGenericPresentations())
            test(vpTokenWithMultipleGenericPresentations(), URI.create("https://redirect.here"))
            test(vpTokenWithMultipleMixedPresentations(), URI.create("https://redirect.here"))
        }

        @Test
        fun `support dcql vp_token`() = runTest {
            suspend fun test(resolvedRequest: ResolvedRequestObject, consensus: Consensus, redirectUri: URI? = null) {
                val dispatcher = Wallet.createDispatcherWithVerifierAsserting(redirectUri) { responseParam ->
                    val jwtClaimsSet = responseParam.assertIsJwtEncryptedWithVerifiersPublicKey().jwtClaimsSet
                    when (consensus) {
                        is Consensus.PositiveConsensus -> {
                            assertEquals(
                                consensus.verifiablePresentations.asJsonObject(),
                                jwtClaimsSet.vpTokenClaim(),
                            )
                        }

                        else -> fail("Expected positive consensus")
                    }
                }

                val expectedOutcome = DispatchOutcome.VerifierResponse.Accepted(redirectUri)
                val outcome = dispatcher.dispatch(
                    resolvedRequest,
                    consensus,
                    EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
                )
                assertEquals(expectedOutcome, outcome)
            }

            val responseMode = ResponseMode.DirectPostJwt("https://respond.here".asHttpsURL().getOrThrow())
            test(
                createOpenID4VPRequestWithDCQL(Verifier.metaDataRequestingEncryptedResponse, responseMode),
                Consensus.PositiveConsensus(dcqlVpTokenWithGenericPresentation()),
            )
        }

        @Test
        fun `unencrypted errors are sent when using direct_post_jwt`() = runTest {
            val responseMode = ResponseMode.DirectPostJwt("https://respond.here".asHttpsURL().getOrThrow())
            val error = ResolutionError.UnknownScope(Scope.OpenId)
            val state = genState()
            val errorDispatchDetails = ErrorDispatchDetails(
                responseMode,
                "nonce",
                state,
                VerifierId.parse("pre-registered").getOrThrow(),
                responseEncryptionSpecification = null,
            )

            val errorDispatcher: ErrorDispatcher = run {
                val mockEngine = MockEngine { request ->
                    val body = assertIs<FormData>(request.body)
                    assertNull(body.formData["response"])
                    assertEquals("invalid_scope", body.formData["error"])
                    assertEquals("UnknownScope(scope=Scope(value=openid))", body.formData["error_description"])
                    assertEquals(state, body.formData["state"])
                    respondOk()
                }
                val httpClient = HttpClient(mockEngine)
                DefaultDispatcherOverHttp(httpClient)
            }

            val dispatchOutcome = errorDispatcher.dispatchError(
                error,
                errorDispatchDetails,
                encryptionParameters = EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
            )
            assertIs<DispatchOutcome.VerifierResponse.Accepted>(dispatchOutcome)
            assertNull(dispatchOutcome.redirectURI)
        }

        private fun vpTokenWithMultipleMixedPresentations(): VerifiablePresentations =
            VerifiablePresentations(
                mapOf(
                    QueryId("psId") to listOf(
                        VerifiablePresentation.Generic("dummy_vp_token"),
                        VerifiablePresentation.JsonObj(
                            buildJsonObject {
                                put("claimString", JsonPrimitive("claim1_value"))
                                put(
                                    "claimArray",
                                    buildJsonArray {
                                        add(JsonPrimitive("array_value_1"))
                                        add(JsonPrimitive("array_value_2"))
                                        add(JsonPrimitive("array_value_3"))
                                    },
                                )
                                put(
                                    "claimObject",
                                    buildJsonObject {
                                        put("child_json_obj_1", JsonPrimitive("val1"))
                                        put("child_json_obj_2", JsonPrimitive("val2"))
                                    },
                                )
                            },
                        ),
                    ),
                ),
            )

        private fun vpTokenWithMultipleGenericPresentations(): VerifiablePresentations =
            VerifiablePresentations(
                mapOf(
                    QueryId("psId") to listOf(
                        VerifiablePresentation.Generic("dummy_vp_token_1"),
                        VerifiablePresentation.Generic("dummy_vp_token_2"),
                        VerifiablePresentation.Generic("dummy_vp_token_3"),
                    ),
                ),
            )

        private fun createOpenID4VPRequestWithDCQL(
            unvalidatedClientMetaData: UnvalidatedClientMetaData,
            responseMode: ResponseMode.DirectPostJwt,
        ): ResolvedRequestObject {
            val query = DCQL(
                credentials = Credentials(
                    testCredentialQuery(),
                ),
            )
            val clientMetadataValidated =
                ClientMetaDataValidator.validateClientMetaData(
                    unvalidatedClientMetaData,
                    responseMode,
                    query,
                    Wallet.config.responseEncryptionConfiguration,
                    Wallet.config.vpConfiguration.vpFormatsSupported,
                )

            return ResolvedRequestObject(
                query = query,
                responseEncryptionSpecification = clientMetadataValidated.responseEncryptionSpecification,
                vpFormatsSupported = VpFormatsSupported(
                    msoMdoc = VpFormatsSupported.MsoMdoc(
                        issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                        deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    ),
                ),
                client = WRP.Random.client,
                nonce = "0S6_WzA2Mj",
                responseMode = responseMode,
                state = genState(),
                transactionData = null,
                verifierInfo = null,
            )
        }

        private fun dcqlVpTokenWithGenericPresentation(): VerifiablePresentations =
            VerifiablePresentations(
                mapOf(
                    QueryId("my_credential") to listOf(VerifiablePresentation.Generic("dummy_vp_token")),
                ),
            )
    }

    @Nested
    @DisplayName("... via DC API")
    inner class DcApiResponse {

        private fun createResolvedRequestObject(
            validatedClientMetaData: ValidatedClientMetaData?,
            query: DCQL,
            state: String,
            responseMode: ResponseMode,
        ): ResolvedRequestObject {
            return ResolvedRequestObject(
                client = Client.Origin(Verifier.CLIENT_ORIGINAL_ID),
                query = query,
                vpFormatsSupported = VpFormatsSupported(
                    msoMdoc = VpFormatsSupported.MsoMdoc(
                        issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                        deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    ),
                ),
                nonce = "0S6_WzA2Mj",
                responseMode = responseMode,
                state = state,
                responseEncryptionSpecification = validatedClientMetaData?.responseEncryptionSpecification,
                transactionData = null,
                verifierInfo = null,
            )
        }

        @Test
        fun `if response mode is dc_api, positive consensus is assembled as vp_token JsonObject`() = runTest {
            val dcApiDispatcher = DefaultDCApiResponseBuilder()

            val state = genState()

            val query = DCQL(
                credentials = Credentials(testCredentialQuery()),
            )

            val resolvedRequestObject = createResolvedRequestObject(
                validatedClientMetaData = null,
                query = query,
                state = state,
                responseMode = ResponseMode.DCApi,
            )

            val consensus = Consensus.PositiveConsensus(
                VerifiablePresentations(
                    mapOf(
                        QueryId("my_credential") to listOf(VerifiablePresentation.Generic("dummy_vp_token")),
                    ),
                ),
            )

            val dcApiResponse = dcApiDispatcher.assembleResponse(resolvedRequestObject, consensus)

            val vpToken = dcApiResponse["vp_token"]
            assertNotNull(vpToken)
            assertIs<JsonObject>(vpToken)

            val queryIdResponse = vpToken["my_credential"]
            assertNotNull(queryIdResponse)
            assertIs<JsonArray>(queryIdResponse)

            val stateInResponse = dcApiResponse["state"]
            assertNotNull(stateInResponse)
            assertIs<JsonPrimitive>(stateInResponse)
            assertEquals(state, stateInResponse.content)
        }

        @Test
        fun `if response mode is dc_api jwt, positive consensus is assembled as an encrypted response embedded in JsonObject`() =
            runTest {
                val dcApiDispatcher = DefaultDCApiResponseBuilder()

                val state = genState()

                val query = DCQL(
                    credentials = Credentials(testCredentialQuery()),
                )

                val clientMetadataValidated =
                    ClientMetaDataValidator.validateClientMetaData(
                        Verifier.metaDataRequestingEncryptedResponse,
                        ResponseMode.DCApiJwt,
                        query,
                        Wallet.config.responseEncryptionConfiguration,
                        Wallet.config.vpConfiguration.vpFormatsSupported,
                    )

                val resolvedRequestObject = createResolvedRequestObject(
                    validatedClientMetaData = clientMetadataValidated,
                    query = query,
                    state = state,
                    responseMode = ResponseMode.DCApiJwt,
                )

                val consensus = Consensus.PositiveConsensus(
                    VerifiablePresentations(
                        mapOf(
                            QueryId("my_credential") to listOf(VerifiablePresentation.Generic("dummy_vp_token")),
                        ),
                    ),
                )

                val apu = "dummy_apu"
                val dcApiResponse = dcApiDispatcher.assembleResponse(
                    resolvedRequestObject,
                    consensus,
                    EncryptionParameters.DiffieHellman(Base64URL.encode(apu)),
                )

                val response = dcApiResponse["response"]
                assertNotNull(response)
                assertIs<JsonPrimitive>(response)

                val encryptedResponse = response.content.assertIsJwtEncryptedWithVerifiersPublicKey()
                assertEquals(
                    Base64URL.encode(resolvedRequestObject.nonce),
                    encryptedResponse.header.agreementPartyVInfo,
                )
                assertEquals(Base64URL.encode(apu), encryptedResponse.header.agreementPartyUInfo)

                val vpTokenJO = encryptedResponse.jwtClaimsSet.getJSONObjectClaim("vp_token")
                assertNotNull(vpTokenJO)

                val queryIdResponse = vpTokenJO["my_credential"]
                assertNotNull(queryIdResponse)
                assertIs<List<String>>(queryIdResponse)

                val stateInResponse = encryptedResponse.jwtClaimsSet.getStringClaim("state")
                assertNotNull(stateInResponse)
                assertEquals(state, stateInResponse)
            }

        @Test
        fun `if response dc_api, negative consensus is assembled as JsonObject`() = runTest {
            val dcApiDispatcher = DefaultDCApiResponseBuilder()

            val state = genState()

            val query = DCQL(
                credentials = Credentials(testCredentialQuery()),
            )

            val resolvedRequestObject = createResolvedRequestObject(
                validatedClientMetaData = null,
                query = query,
                state = state,
                responseMode = ResponseMode.DCApi,
            )

            val dcApiResponse = dcApiDispatcher.assembleResponse(resolvedRequestObject, Consensus.NegativeConsensus)
            val error = dcApiResponse["error"]
            assertNotNull(error)
            assertIs<JsonPrimitive>(error)
            assertEquals("access_denied", error.content)

            val stateInResponse = dcApiResponse["state"]
            assertNotNull(stateInResponse)
            assertIs<JsonPrimitive>(stateInResponse)
            assertEquals(state, stateInResponse.content)
        }

        @Test
        fun `dc api errors are assembled as json objects`() {
            val dcApiDispatcher = DefaultDCApiResponseBuilder()
            val validationError = RequestValidationError.UnexpectedOrigin
            val errorResponse = dcApiDispatcher.assembleErrorResponse(validationError)

            val error = errorResponse["error"]
            assertNotNull(error)
            assertIs<JsonPrimitive>(error)
            assertEquals("invalid_request", error.content)
        }
    }
}

private fun genState(): String = State().value
private fun JWTClaimsSet.vpTokenClaim(): JsonElement? =
    Json.parseToJsonElement(toString()).jsonObject["vp_token"]

private fun testCredentialQuery(): CredentialQuery = CredentialQuery(
    QueryId("my_credential"),
    Format.SdJwtVc,
    meta = JsonObject(
        mapOf(
            "vct_values" to
                JsonArray(
                    listOf(
                        JsonPrimitive("https://credentials.example.com/identity_credential"),
                    ),
                ),
        ),
    ),
    claims = listOf(
        ClaimsQuery(
            path = ClaimPath(listOf(Claim("last_name"))),
        ),
        ClaimsQuery(
            path = ClaimPath(listOf(Claim("first_name"))),
        ),
        ClaimsQuery(
            path = ClaimPath(listOf(Claim("address"), Claim("street_address"))),
        ),
    ),
)
