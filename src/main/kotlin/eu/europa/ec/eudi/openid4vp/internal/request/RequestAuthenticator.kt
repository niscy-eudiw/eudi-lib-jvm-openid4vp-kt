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

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.BadJWTException
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier
import com.nimbusds.jwt.util.DateUtils
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.RequestValidationError.NoMatchingClientPrefixInMultiSignedRequest
import eu.europa.ec.eudi.openid4vp.internal.*
import eu.europa.ec.eudi.openid4vp.internal.JwsJson.Companion.flatten
import eu.europa.ec.eudi.openid4vp.internal.request.AuthenticatedClient.X509Hash
import eu.europa.ec.eudi.openid4vp.internal.request.AuthenticatedClient.X509SanDns
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.time.Clock
import java.util.*
import kotlin.time.Duration
import kotlin.time.toKotlinDuration

internal sealed interface AuthenticatedClient {
    data class X509SanDns(val clientId: OriginalClientId, val chain: List<X509Certificate>) : AuthenticatedClient
    data class X509Hash constructor(val clientId: OriginalClientId, val chain: List<X509Certificate>) : AuthenticatedClient
}

internal data class AuthenticatedRequest(
    val client: AuthenticatedClient,
    val requestObject: UnvalidatedRequestObject,
)

internal class RequestAuthenticator private constructor(
    private val clientAuthenticator: ClientAuthenticator,
    private val signatureVerifier: JarJwtSignatureVerifier,
) {

    suspend fun authenticateRequestOverDCApi(request: ReceivedRequest): AuthenticatedRequest {
        val (client, signedJwt) = clientAuthenticator.authenticateClientOverDCApi(request)
        requireNotNull(signedJwt) {
            "Expected a signed request but was not."
        }
        with(signatureVerifier) {
            verifySignature(client, signedJwt)
        }
        val requestObject = when (request) {
            is ReceivedRequest.Signed -> signedJwt.requestObject()
            is ReceivedRequest.MultiSigned -> signedJwt.requestObject().extendWithHeaderAttributes(signedJwt.header)
        }
        return AuthenticatedRequest(client, requestObject)
    }

    suspend fun authenticateRequestOverHttp(request: ReceivedRequest): AuthenticatedRequest = coroutineScope {
        val client = clientAuthenticator.authenticateClientOverHttp(request)
        when (request) {
            is ReceivedRequest.Signed -> {
                val signedJwt = request.jwsJson.toSignedJwt()
                with(signatureVerifier) { verifySignature(client, signedJwt) }
                AuthenticatedRequest(client, signedJwt.requestObject())
            }

            is ReceivedRequest.MultiSigned -> {
                error("Multisigned requests are not expected over redirects.")
            }
        }
    }

    companion object {
        operator fun invoke(openId4VPConfig: OpenId4VPConfig) = RequestAuthenticator(
            clientAuthenticator = ClientAuthenticator(openId4VPConfig),
            signatureVerifier = JarJwtSignatureVerifier(openId4VPConfig),
        )
    }
}

internal class ClientAuthenticator(private val openId4VPConfig: OpenId4VPConfig) {

    /**
     * In case of DC API channel client_id is present per case:
     * - When request is unsinged is not included in request and is implied to be 'origin:<origin as passed from DC API call>'
     * - When request is a JWS in compact serialization client_id is expected to exist in claims
     * - When request is a JWS in JSON serialization client_id must exist in the header of each signature
     */
    suspend fun authenticateClientOverDCApi(
        request: ReceivedRequest,
    ): Pair<AuthenticatedClient, SignedJWT?> =
        when (request) {
            is ReceivedRequest.Signed -> {
                val signedJwt = request.jwsJson.toSignedJwt()
                val (originalClientId, clientIdPrefix) = originalClientIdAndPrefix(signedJwt.requestObject())
                authenticateClientPrefix(originalClientId, clientIdPrefix, signedJwt) to signedJwt
            }

            is ReceivedRequest.MultiSigned -> {
                val policy = openId4VPConfig.signedRequestConfiguration.multiSignedRequestsPolicy
                val (originalClientId, clientIdPrefix, signedJwt) = request.jwsJson apply policy
                authenticateClientPrefix(originalClientId, clientIdPrefix, signedJwt) to signedJwt
            }
        }

    private infix fun JwsJson.General.apply(
        policy: MultiSignedRequestsPolicy,
    ): Triple<OriginalClientId, SupportedClientIdPrefix, SignedJWT> =
        when (policy) {
            is MultiSignedRequestsPolicy.Expect ->
                matchExpectedClientPrefix(policy.clientPrefix)

            MultiSignedRequestsPolicy.NotSupported ->
                throw RequestValidationError.MultiSignedRequestsNotSupported.asException()
        }

    /**
     * In case of HTTP channel client_id is mandatory to always exist.
     */
    suspend fun authenticateClientOverHttp(request: ReceivedRequest): AuthenticatedClient {
        val (signedRequest, requestObject) = when (request) {
            is ReceivedRequest.Signed -> {
                val signedRequest = request.jwsJson.toSignedJwt()
                signedRequest to signedRequest.requestObject()
            }

            is ReceivedRequest.MultiSigned ->
                error("Multisigned requests are not expected over redirects.")
        }
        val (originalClientId, clientIdPrefix) = originalClientIdAndPrefix(requestObject)
        return authenticateClientPrefix(originalClientId, clientIdPrefix, signedRequest)
    }

    private fun JwsJson.General.matchExpectedClientPrefix(
        expectedPrefix: ClientIdPrefix,
    ): Triple<OriginalClientId, SupportedClientIdPrefix, SignedJWT> =
        flatten().map { flattened ->
            flattened.clientIdFromProtectedHeader()?.let { clientId ->
                val verifierId = VerifierId.parse(clientId).getOrElse {
                    throw invalidPrefix("Invalid client_id: ${it.message}")
                }
                if (verifierId.prefix == expectedPrefix) {
                    val supportedClientIdPrefix = openId4VPConfig.supportedClientIdPrefix(verifierId.prefix)
                    ensureNotNull(supportedClientIdPrefix) { RequestValidationError.UnsupportedClientIdPrefix.asException() }
                    Triple(verifierId.originalClientId, supportedClientIdPrefix, flattened.toSignedJwt())
                } else
                    null
            }
        }.firstOrNull()
            ?: throw NoMatchingClientPrefixInMultiSignedRequest.asException()

    private fun JwsJson.Flattened.clientIdFromProtectedHeader(): String? {
        val protectedHeader = protected?.decodeAs<JsonObject>()
        return protectedHeader?.get("client_id")?.let {
            ensure(it is JsonPrimitive) { error("Invalid client_id") }
            it.content
        }
    }

    private suspend fun authenticateClientPrefix(
        originalClientId: OriginalClientId,
        clientIdPrefix: SupportedClientIdPrefix,
        signedRequest: SignedJWT?,
    ): AuthenticatedClient =
        when (clientIdPrefix) {
            is SupportedClientIdPrefix.X509SanDns -> {
                ensure(signedRequest != null) {
                    invalidPrefix("${clientIdPrefix.prefix()} cannot be used in unsigned request")
                }
                val chain = x5c(signedRequest, clientIdPrefix.trust)

                val alternativeNames = chain.first().sanOfDNSName().getOrNull()
                ensureNotNull(alternativeNames) { invalidJarJwt("Certificates misses DNS names") }
                ensure(originalClientId in alternativeNames) {
                    invalidJarJwt("ClientId not found in certificate's subject alternative names")
                }

                X509SanDns(originalClientId, chain)
            }

            is SupportedClientIdPrefix.X509Hash -> {
                ensure(signedRequest != null) {
                    invalidPrefix("${clientIdPrefix.prefix()} cannot be used in unsigned request")
                }
                val chain = x5c(signedRequest, clientIdPrefix.trust)

                val expectedHash = base64UrlNoPadding.encode(
                    MessageDigest.getInstance("SHA-256").digest(chain.first().encoded),
                )
                ensure(expectedHash == originalClientId) {
                    invalidJarJwt("ClientId does not match leaf certificate's SHA-256 hash")
                }

                X509Hash(originalClientId, chain)
            }
        }

    private fun originalClientIdAndPrefix(requestObject: UnvalidatedRequestObject): Pair<OriginalClientId, SupportedClientIdPrefix> {
        val clientId = ensureNotNull(requestObject.clientId) {
            RequestValidationError.MissingClientId.asException()
        }
        val verifierId =
            VerifierId.parse(clientId).getOrElse { throw invalidPrefix("Invalid client_id: ${it.message}") }
        val supportedClientIdPrefix = openId4VPConfig.supportedClientIdPrefix(verifierId.prefix)
        ensureNotNull(supportedClientIdPrefix) { RequestValidationError.UnsupportedClientIdPrefix.asException() }
        return verifierId.originalClientId to supportedClientIdPrefix
    }

    private suspend fun x5c(
        requestJwt: SignedJWT,
        trust: X509CertificateTrust,
    ): List<X509Certificate> {
        val x5c = requestJwt.header?.x509CertChain
        ensureNotNull(x5c) { invalidJarJwt("Missing x5c") }
        val pubCertChain = x5c.mapNotNull { runCatchingCancellable { X509CertUtils.parse(it.decode()) }.getOrNull() }
        ensure(pubCertChain.isNotEmpty()) { invalidJarJwt("Invalid x5c") }
        withContext(Dispatchers.IO.limitedParallelism(1)) {
            ensure(trust.isTrusted(pubCertChain)) { invalidJarJwt("Untrusted x5c") }
        }
        return pubCertChain
    }
}

/**
 * Validates a JWT that represents an Authorization Request according to RFC9101
 *
 * @param openId4VPConfig wallet's configuration
 */
private class JarJwtSignatureVerifier(
    private val openId4VPConfig: OpenId4VPConfig,
) {

    @Throws(AuthorizationRequestException::class)
    fun verifySignature(client: AuthenticatedClient, signedJwt: SignedJWT) {
        try {
            val jwtProcessor = DefaultJWTProcessor<SecurityContext>().apply {
                jwsTypeVerifier =
                    DefaultJOSEObjectTypeVerifier(JOSEObjectType(OpenId4VPSpec.AUTHORIZATION_REQUEST_OBJECT_TYPE))
                jwsKeySelector = jwsKeySelector(client)
                jwtClaimsSetVerifier =
                    TimeChecks(
                        openId4VPConfig.clock,
                        openId4VPConfig.signedRequestConfiguration.clockSkew.toKotlinDuration(),
                    )
            }
            jwtProcessor.process(signedJwt, null)
        } catch (e: JOSEException) {
            throw RuntimeException(e)
        } catch (e: BadJOSEException) {
            throw invalidJarJwt("Invalid signature ${e.message}")
        }
    }

    @Throws(AuthorizationRequestException::class)
    private fun jwsKeySelector(client: AuthenticatedClient): JWSKeySelector<SecurityContext> =
        when (client) {
            is X509SanDns ->
                JWSKeySelector<SecurityContext> { _, _ -> listOf(client.chain[0].publicKey) }

            is X509Hash ->
                JWSKeySelector<SecurityContext> { _, _ -> listOf(client.chain[0].publicKey) }
        }
}

private fun invalidPrefix(cause: String): AuthorizationRequestException =
    RequestValidationError.InvalidClientIdPrefix(cause).asException()

private fun invalidJarJwt(cause: String): AuthorizationRequestException =
    RequestValidationError.InvalidJarJwt(cause).asException()

internal fun SignedJWT.requestObject(): UnvalidatedRequestObject =
    jsonSupport.decodeFromString(JSONObjectUtils.toJSONString(jwtClaimsSet.toJSONObject()))

private fun UnvalidatedRequestObject.extendWithHeaderAttributes(header: JWSHeader?): UnvalidatedRequestObject =
    header?.getCustomParam(OpenId4VPSpec.VERIFIER_INFO)
        ?.let { verifierInfo ->
            ensure(verifierInfo is JsonObject) {
                error("Invalid verifier_info. Expected JsonObject but was ${verifierInfo::class}")
            }
            val verifierInfo = jsonSupport.decodeFromString<VerifierInfoTO>(JSONObjectUtils.toJSONString(verifierInfo))
            this.copy(verifierInfo = verifierInfo)
        } ?: this

private class TimeChecks(
    private val clock: Clock,
    private val skew: Duration,
) : JWTClaimsSetVerifier<SecurityContext> {

    @Throws(BadJWTException::class)
    override fun verify(claimsSet: JWTClaimsSet, context: SecurityContext?) {
        val now = Date.from(clock.instant())
        val skewInSeconds = skew.inWholeSeconds

        val exp = claimsSet.expirationTime
        if (exp != null && !DateUtils.isAfter(exp, now, skewInSeconds)) {
            throw BadJWTException("Expired JWT")
        }

        val nbf = claimsSet.notBeforeTime
        if (nbf != null && !DateUtils.isBefore(nbf, now, skewInSeconds)) {
            throw BadJWTException("JWT before use time")
        }
    }
}
