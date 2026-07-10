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
package eu.europa.ec.eudi.openid4vp

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.MessageDigest
import java.security.Security
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*
import kotlin.lazy

internal data class WRP(val accessCertificate: AccessCertificate) {

    data class AccessCertificate(
        val algorithm: JWSAlgorithm,
        val key: ECKey,
        val chain: List<X509Certificate>,
    )

    val client: Client by lazy {
        val originalClientId = calculateHash(accessCertificate.chain[0])
        Client.X509Hash(originalClientId, accessCertificate.chain[0])
    }

    val clientId: String by lazy { "x509_san_dns:${client.id}" }

    companion object {
        val Random by lazy { random() }

        private fun random(): WRP {
            val accessCertificate = randomAccessCertificate()
            return WRP(accessCertificate)
        }

        fun randomAccessCertificate(): AccessCertificate {
            Security.addProvider(BouncyCastleProvider())
            val key = ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).generate()
            val publicKey = key.toPublicKey()
            val certificateChain = generateCertificateChain(publicKey)

            val algorithm = JWSAlgorithm.ES256
            return AccessCertificate(algorithm, key, certificateChain)
        }
    }
}

internal fun WRP.schemeSigner(headerCustomization: (JWSHeader.Builder).() -> Unit = {}): SchemeSigner = SchemeSigner(
    alg = accessCertificate.algorithm,
    key = accessCertificate.key,
    headerCustomization,
)

private fun calculateHash(c: X509Certificate): String {
    val derEncoded = c.encoded
    val messageDigest = MessageDigest.getInstance("SHA-256")
    val hash = messageDigest.digest(derEncoded)
    return Base64.getUrlEncoder().withoutPadding().encodeToString(hash)
}
private fun generateCertificateChain(
    leafPublicKey: java.security.PublicKey,

): List<X509Certificate> {
    val rootKeyPair = ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).generate().toKeyPair()
    val rootPublicKey = rootKeyPair.public
    val rootPrivateKey = rootKeyPair.private

    val rootCertificate = generateCertificate(
        subjectDN = X500Name("CN=Root CA, O=Test Org, C=US"),
        issuerDN = X500Name("CN=Root CA, O=Test Org, C=US"), // Self-signed
        publicKey = rootPublicKey,
        signingPrivateKey = rootPrivateKey,
        validityDays = 365 * 10, // 10 years
    )

    val leafCertificate = generateCertificate(
        subjectDN = X500Name("CN=Leaf Certificate, O=Test Org, C=US"),
        issuerDN = X500Name("CN=Root CA, O=Test Org, C=US"),
        publicKey = leafPublicKey,
        signingPrivateKey = rootPrivateKey, // Signed by Root CA
        validityDays = 365, // 1 year
    )

    return listOf(leafCertificate, rootCertificate)
}

private fun generateCertificate(
    subjectDN: X500Name,
    issuerDN: X500Name,
    publicKey: java.security.PublicKey,
    signingPrivateKey: java.security.PrivateKey,
    validityDays: Long,
): X509Certificate {
    // Serial number (random positive BigInteger)
    val serialNumber = BigInteger(64, Random()).abs()

    // Validity period
    val notBefore = Date.from(Instant.now())
    val notAfter = Date.from(Instant.now().plus(validityDays, ChronoUnit.DAYS))

    // Build certificate
    val certBuilder = X509v3CertificateBuilder(
        issuerDN,
        serialNumber,
        notBefore,
        notAfter,
        subjectDN,
        SubjectPublicKeyInfo.getInstance(publicKey.encoded),
    )

    val signer = JcaContentSignerBuilder("SHA256withECDSA")
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .build(signingPrivateKey)

    val certHolder = certBuilder.build(signer)

    return JcaX509CertificateConverter()
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .getCertificate(certHolder)
}
