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

import com.eygraber.uri.Uri
import com.eygraber.uri.Url
import com.eygraber.uri.toKmpUri
import eu.europa.ec.eudi.openid4vp.Format
import eu.europa.ec.eudi.openid4vp.dcql.ClaimPath
import eu.europa.ec.eudi.openid4vp.dcql.DCQLMetaMsoMdocExtensions
import eu.europa.ec.eudi.openid4vp.dcql.DCQLMetaSdJwtVcExtensions
import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import eu.europa.ec.eudi.openid4vp.runCatchingCancellable
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.decodeFromJsonElement
import java.util.Locale
import kotlin.time.Instant

@Serializable
data class WalletRelyingPartyRegistrationCertificateClaims(
    @Required @SerialName(ETSI119475.TRADE_NAME_CLAIM) val tradeName: String,
    @SerialName(ETSI119475.LEGAL_NAME_CLAIM) val legalName: String? = null,
    @SerialName(ETSI119475.GIVEN_NAME_CLAIM) val givenName: String? = null,
    @SerialName(ETSI119475.FAMILY_NAME_CLAIM) val familyName: String? = null,
    @Required @SerialName(ETSI119475.IDENTIFIER_CLAIM) val identifier: String,
    @Required @SerialName(ETSI119475.COUNTRY_CLAIM) val country: CountryCode,
    @Required @SerialName(ETSI119475.REGISTRY_URI_CLAIM) val registry: Url,
    @Required @SerialName(ETSI119475.SERVICE_DESCRIPTION_CLAIM) val serviceDescription: ServiceDescription,
    @Required @SerialName(ETSI119475.ENTITLEMENTS_CLAIM) val entitlements: Entitlements,
    @Required @SerialName(ETSI119475.PRIVACY_POLICY_CLAIM) val privacyPolicy: Url,
    @Required @SerialName(ETSI119475.INFO_URI_CLAIM) val info: Url,
    @Required @SerialName(ETSI119475.SUPPORT_URI_CLAIM) val support: Url,
    @Required @SerialName(ETSI119475.SUPERVISORY_AUTHORITY_CLAIM) val supervisoryAuthority: SupervisoryAuthority,
    @Required @SerialName(ETSI119475.POLICY_ID_CLAIM) val policies: CertificatePolicies,
    @Required @SerialName(ETSI119475.CERTIFICATE_POLICY_CLAIM) val certificatePolicy: Url,
    @Required @SerialName(RFC7519.ISSUED_AT_CLAIM) val issuedAt: EpochSecondsInstant,
    @Required @SerialName(TokenStatusList.STATUS_CLAIM) val status: Status,
    @SerialName(ETSI119475.PROVIDES_ATTESTATIONS_CLAIM) val providesAttestations: ProvidedAttestations? = null,
    @SerialName(ETSI119475.CREDENTIALS_CLAIM) val credentials: Credentials? = null,
    @SerialName(ETSI119475.PURPOSE_CLAIM) val purpose: Purpose? = null,
    @SerialName(ETSI119475.INTENDED_USE_ID_CLAIM) val intendedUse: String? = null,
    @SerialName(ETSI119475.PUBLIC_BODY_CLAIM) val publicSectorBody: Boolean? = null,
    @SerialName(RFC7519.EXPIRES_AT_CLAIM) val expiresAt: EpochSecondsInstant? = null,
    @SerialName(ETSI119475.INTERMEDIARY_CLAIM) val intermediaries: Intermediary? = null,
) {
    init {
        require(
            (null != legalName && null == givenName && null == familyName) ||
                (null == legalName && null != givenName && null != familyName),
        )

        if (entitlements.intersect(Entitlement.AttestationProvisioningEntitlements).isNotEmpty()) {
            require(null != providesAttestations)
        } else {
            require(null == providesAttestations)
        }

        require((null == credentials && null == purpose) || (null != credentials && null != purpose))
        if (null != intendedUse) {
            require(null != credentials && null != purpose)
        }
    }
}

val WalletRelyingPartyRegistrationCertificateClaims.legalPerson: Boolean
    get() = null != legalName

val WalletRelyingPartyRegistrationCertificateClaims.naturalPerson: Boolean
    get() = null != givenName && null != familyName

val WalletRelyingPartyRegistrationCertificateClaims.attestationProvider: Boolean
    get() = null != providesAttestations

@Serializable
@JvmInline
value class CountryCode(val code: String) {
    init {
        require(code.matches("[A-Z]{2}".toRegex()))
    }
}

@Serializable
@JvmInline
value class ServiceDescription(val descriptions: List<MultiLangString>) : Iterable<MultiLangString> by descriptions {
    init {
        require(descriptions.isNotEmpty())
    }
}

@Serializable
data class MultiLangString(
    @Required @SerialName(ETSI119475.MULTILANG_STRING_LANG_CLAIM) val lang: LanguageTag,
    @Required @SerialName(ETSI119475.MULTILANG_STRING_VALUE_CLAIM) val content: String,
)

@Serializable
@JvmInline
value class LanguageTag(
    @Serializable(with = LocaleLanguageTagSerializer::class) val tag: Locale,
) {
    init {
        require(tag.isValid())
    }

    companion object {
        fun Locale.isValid() =
            runCatchingCancellable {
                Locale.Builder().setLanguageTag(toLanguageTag()).build()
                true
            }.getOrElse { false }
    }
}

object LocaleLanguageTagSerializer : KSerializer<Locale> {
    override val descriptor: SerialDescriptor
        get() = PrimitiveSerialDescriptor("LocaleLanguageTag", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Locale) {
        encoder.encodeString(value.toLanguageTag())
    }

    override fun deserialize(decoder: Decoder): Locale = Locale.Builder().setLanguageTag(decoder.decodeString()).build()
}

@Serializable
@JvmInline
value class Entitlements(val entitlements: List<Entitlement>) : Iterable<Entitlement> by entitlements {
    init {
        require(entitlements.isNotEmpty())
        require(entitlements.intersect(Entitlement.WalletRelyingPartyEntitlements).isNotEmpty())
        if (Entitlement.ServiceProvider in entitlements) {
            require(entitlements.intersect(Entitlement.ServiceProviderSubEntitlements).isNotEmpty())
        }
    }
}

@Serializable
@JvmInline
value class Entitlement(val uri: Uri) {
    companion object {
        // General service provider
        val ServiceProvider = Entitlement(ETSI119475.SERVICE_PROVIDER_ENTITLEMENT_URI.toKmpUri())

        // Qualified trust service provider issuing qualified electronic attestations of attributes
        val QEAAProvider = Entitlement(ETSI119475.QEAA_PROVIDER_ENTITLEMENT_URI.toKmpUri())

        // Trust service provider issuing non-qualified electronic attestations of attributes
        val NonQEAAProvider = Entitlement(ETSI119475.NON_QEAA_PROVIDER_ENTITLEMENT_URI.toKmpUri())

        // Public sector body or its agent issuing electronic attestations of attributes from authentic sources
        val PubEAAProvider = Entitlement(ETSI119475.PUB_EAA_PROVIDER_ENTITLEMENT_URI.toKmpUri())

        // Provider of person identification data
        val PIDProvider = Entitlement(ETSI119475.PID_PROVIDER_ENTITLEMENT_URI.toKmpUri())

        // QTSP issuing qualified certificates for electronic seals
        val QCertForESealProvider = Entitlement(ETSI119475.QCERT_FOR_ESEAL_PROVIDER_ENTITLEMENT_URI.toKmpUri())

        // QTSP issuing qualified certificates for electronic signatures
        val QCertForESigProvider = Entitlement(ETSI119475.QCERT_FOR_ESIG_PROVIDER_ENTITLEMENT_URI.toKmpUri())

        // QTSP managing remote qualified electronic seal creation devices
        val rQSealCDsProvider = Entitlement(ETSI119475.RQSEALCDS_PROVIDER_ENTITLEMENT_URI.toKmpUri())

        // QTSP managing remote qualified electronic signature creation devices
        val rQSigCDsProvider = Entitlement(ETSI119475.RQSIGCDS_PROVIDER_ENTITLEMENT_URI.toKmpUri())

        // Non-qualified provider for remote signature/seal creation
        val ESigESealCreationProvider = Entitlement(ETSI119475.ESIG_ESEAL_CREATION_PROVIDER_ENTITLEMENT_URI.toKmpUri())

        // Entitlements for Wallet Relying Parties
        val WalletRelyingPartyEntitlements = setOf(
            ServiceProvider,
            QEAAProvider,
            NonQEAAProvider,
            PubEAAProvider,
            PIDProvider,
            QCertForESealProvider,
            QCertForESigProvider,
            rQSealCDsProvider,
            rQSigCDsProvider,
            ESigESealCreationProvider,
        )

        // Entitlements for Wallet Relying Parties tha Provision Attestations
        val AttestationProvisioningEntitlements = setOf(
            PIDProvider,
            QEAAProvider,
            NonQEAAProvider,
            PubEAAProvider,
        )

        // Account Servicing Payment Service Provider
        val AccountServicingPaymentServiceProvider =
            Entitlement(ETSI119475.ACCOUNT_SERVICING_PAYMENT_SERVICE_PROVIDER_ENTITLEMENT_URI.toKmpUri())

        // Payment Initiation Service Provider
        val PaymentInitiationServiceProvider = Entitlement(ETSI119475.PAYMENT_INITIATION_SERVICE_PROVIDER_ENTITLEMENT_URI.toKmpUri())

        // Account Information Service Provider
        val AccountInformationServiceProvider = Entitlement(ETSI119475.ACCOUNT_INFORMATION_SERVICE_PROVIDER_ENTITLEMENT_URI.toKmpUri())

        // Payment Service Provider issuing card-based payment instruments
        val PaymentServiceProviderIssuingCardBasedPaymentInstruments = Entitlement(
            ETSI119475.PAYMENT_SERVICE_PROVIDER_ISSUING_CARD_BASED_PAYMENT_INSTRUMENTS_ENTITLEMENT_URI.toKmpUri(),
        )

        // Unspecified Payment Service Provider
        val UnspecifiedPaymentServiceProvider = Entitlement(ETSI119475.UNSPECIFIED_PAYMENT_SERVICE_PROVIDER_ENTITLEMENT_URI.toKmpUri())

        // Sub Entitlements for Service Providers
        val ServiceProviderSubEntitlements = setOf(
            AccountServicingPaymentServiceProvider,
            PaymentInitiationServiceProvider,
            AccountInformationServiceProvider,
            PaymentServiceProviderIssuingCardBasedPaymentInstruments,
            UnspecifiedPaymentServiceProvider,
        )
    }
}

val Entitlement.oid: String?
    get() = when (this) {
        Entitlement.ServiceProvider -> ETSI119475.SERVICE_PROVIDER_ENTITLEMENT_OID
        Entitlement.QEAAProvider -> ETSI119475.QEAA_PROVIDER_ENTITLEMENT_OID
        Entitlement.NonQEAAProvider -> ETSI119475.NON_QEAA_PROVIDER_ENTITLEMENT_OID
        Entitlement.PubEAAProvider -> ETSI119475.PUB_EAA_PROVIDER_ENTITLEMENT_OID
        Entitlement.PIDProvider -> ETSI119475.PID_PROVIDER_ENTITLEMENT_OID
        Entitlement.QCertForESealProvider -> ETSI119475.QCERT_FOR_ESEAL_PROVIDER_ENTITLEMENT_OID
        Entitlement.QCertForESigProvider -> ETSI119475.QCERT_FOR_ESIG_PROVIDER_ENTITLEMENT_OID
        Entitlement.rQSealCDsProvider -> ETSI119475.RQSEALCDS_PROVIDER_ENTITLEMENT_OID
        Entitlement.rQSigCDsProvider -> ETSI119475.RQSIGCDS_PROVIDER_ENTITLEMENT_OID
        Entitlement.ESigESealCreationProvider -> ETSI119475.ESIG_ESEAL_CREATION_PROVIDER_ENTITLEMENT_OID
        else -> null
    }

@Serializable
data class SupervisoryAuthority(
    @Required @SerialName(ETSI119475.SUPERVISOR_AUTHORITY_EMAIL_CLAIM) val email: String,
    @Required @SerialName(ETSI119475.SUPERVISOR_AUTHORITY_PHONE_CLAIM) val phone: String,
    @Required @SerialName(ETSI119475.SUPERVISOR_AUTHORITY_URI_CLAIM) val uri: Url,
)

@Serializable
@JvmInline
value class CertificatePolicy(val oid: String) {
    companion object {
        // ETSI Certificate Policy for Wallet Relying Parties
        val WalletRelyingParty = CertificatePolicy(ETSI119475.WALLET_RELYING_PARTY_CERTIFICATE_POLICY_OID)
    }
}

@Serializable
@JvmInline
value class CertificatePolicies(val policies: List<CertificatePolicy>) : Iterable<CertificatePolicy> by policies {
    init {
        require(policies.isNotEmpty())
        require(CertificatePolicy.WalletRelyingParty in policies)
    }
}

typealias EpochSecondsInstant =
    @Serializable(with = InstantEpochSecondsSerializer::class)
    Instant

object InstantEpochSecondsSerializer : KSerializer<Instant> {
    override val descriptor: SerialDescriptor
        get() = PrimitiveSerialDescriptor("InstantEpochSeconds", PrimitiveKind.LONG)

    override fun serialize(encoder: Encoder, value: Instant) {
        encoder.encodeLong(value.epochSeconds)
    }

    override fun deserialize(decoder: Decoder): Instant =
        Instant.fromEpochSeconds(decoder.decodeLong(), 0L)
}

@Serializable
data class Status(
    @Required @SerialName(TokenStatusList.STATUS_LIST_CLAIM) val statusList: StatusList,
) {
    @Serializable
    data class StatusList(
        @Required @SerialName(TokenStatusList.STATUS_LIST_INDEX_CLAIM) val index: ULong,
        @Required @SerialName(TokenStatusList.STATUS_LIST_URI_CLAIM) val uri: Uri,
    )
}

@Serializable
@JvmInline
value class ProvidedAttestations(val attestations: List<Credential>) : Iterable<Credential> by attestations {
    init {
        require(attestations.isNotEmpty())
    }
}

@Serializable
@JvmInline
value class Credentials(val credentials: List<Credential>) : Iterable<Credential> by credentials {
    init {
        require(credentials.isNotEmpty())
    }
}

@Serializable
data class Credential(
    @Required @SerialName(ETSI119475.CREDENTIAL_FORMAT_CLAIM) val format: Format,
    @Required @SerialName(ETSI119475.CREDENTIAL_META_CLAIM) val meta: JsonObject,
    @SerialName(ETSI119475.CREDENTIAL_CLAIM_CLAIM) val claim: Claims? = null,
)

val Credential.msoMDocMeta: DCQLMetaMsoMdocExtensions
    get() = jsonSupport.decodeFromJsonElement<DCQLMetaMsoMdocExtensions>(meta)

val Credential.sdJwtVcMeta: DCQLMetaSdJwtVcExtensions
    get() = jsonSupport.decodeFromJsonElement<DCQLMetaSdJwtVcExtensions>(meta)

@Serializable
@JvmInline
value class Claims(val claims: List<Claim>) : Iterable<Claim> by claims {
    init {
        require(claims.isNotEmpty())
    }
}

@Serializable
data class Claim(
    @Required @SerialName(ETSI119475.CLAIM_PATH_CLAIM) val path: ClaimPath,
    @SerialName(ETSI119475.CLAIM_VALUES_CLAIM) val values: Values? = null,
)

@Serializable
@JvmInline
value class Values(val values: List<JsonPrimitive>) : Iterable<JsonPrimitive> by values {
    init {
        require(values.isNotEmpty() && values.none { JsonNull == it })
    }
}

@Serializable
@JvmInline
value class Purpose(val purpose: List<MultiLangString>) : Iterable<MultiLangString> by purpose {
    init {
        require(purpose.isNotEmpty())
    }
}

@Serializable
data class Intermediary(
    @Required @SerialName(ETSI119475.INTERMEDIATE_IDENTIFIER_CLAIM) val identifier: String,
    @Required @SerialName(ETSI119475.INTERMEDIATE_NAME_CLAIM) val name: String,
)
