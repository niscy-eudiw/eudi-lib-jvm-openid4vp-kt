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
package eu.europa.ec.eudi.openid4vp.wrprc

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import eu.europa.ec.eudi.openid4vp.runCatchingCancellable
import java.security.cert.X509Certificate

@JvmInline
value class CertificateChain(val chain: List<X509Certificate>) {
    init {
        require(chain.isNotEmpty())
    }
}

data class WalletRelyingPartyRegistrationCertificate private constructor(
    val certificate: SignedJWT,
    val certificateChain: CertificateChain,
    val claims: WalletRelyingPartyRegistrationCertificateClaims,
) {
    val signingCertificate: X509Certificate
        get() = certificateChain.chain.first()

    companion object {
        fun parseOrNull(value: String): WalletRelyingPartyRegistrationCertificate? = tryParse(value).getOrNull()
        fun parse(value: String): WalletRelyingPartyRegistrationCertificate = tryParse(value).getOrThrow()

        fun tryParse(value: String): Result<WalletRelyingPartyRegistrationCertificate> =
            runCatchingCancellable {
                val certificate = SignedJWT.parse(value)

                val type: JOSEObjectType? = certificate.header.type
                require(JOSEObjectType(ETSI119475.WALLET_RELYING_PARTY_REGISTRATION_CERTIFICATE_TYPE) == type) {
                    "Unexpected type. Expected: '${ETSI119475.WALLET_RELYING_PARTY_REGISTRATION_CERTIFICATE_TYPE}', got: '${type?.type}'."
                }

                val x5c = certificate.header.x509CertChain?.map { X509CertUtils.parseWithException(it.decode()) }
                require(!x5c.isNullOrEmpty()) { "Missing 'x5c' claim in the header" }

                val verifier = DefaultJWSVerifierFactory().createJWSVerifier(certificate.header, x5c.first().publicKey)
                require(certificate.verify(verifier))

                val claims = jsonSupport.decodeFromString<WalletRelyingPartyRegistrationCertificateClaims>(
                    JSONObjectUtils.toJSONString(certificate.jwtClaimsSet.toJSONObject()),
                )

                WalletRelyingPartyRegistrationCertificate(certificate, CertificateChain(x5c), claims)
            }
    }
}
