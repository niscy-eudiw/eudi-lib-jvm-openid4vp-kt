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
    @Required @SerialName(ETSI119475.SERVICE_DESCRIPTIONS_CLAIM) val serviceDescriptions: List<MultiLangString>,
    @Required @SerialName(ETSI119475.ENTITLEMENTS_CLAIM) val entitlements: List<Entitlement>,
    @Required @SerialName(ETSI119475.PRIVACY_POLICY_CLAIM) val privacyPolicy: Url,
    @Required @SerialName(ETSI119475.INFO_URI_CLAIM) val info: Url,
    @Required @SerialName(ETSI119475.SUPPORT_URI_CLAIM) val support: Url,
    @Required @SerialName(ETSI119475.SUPERVISORY_AUTHORITY_CLAIM) val supervisoryAuthority: SupervisoryAuthority,
    @Required @SerialName(ETSI119475.POLICY_ID_CLAIM) val policies: List<CertificatePolicy>,
    @Required @SerialName(ETSI119475.CERTIFICATE_POLICY_CLAIM) val certificatePolicy: Url,
    @Required @SerialName(RFC7519.ISSUED_AT_CLAIM) @Serializable(with = InstantEpochSecondsSerializer::class) val issuedAt: Instant,
    @Required @SerialName(TokenStatusList.STATUS_CLAIM) val status: Status,
    @SerialName(ETSI119475.PROVIDES_ATTESTATIONS_CLAIM) val providesAttestations: List<Credential>? = null,
    @SerialName(ETSI119475.CREDENTIALS_CLAIM) val credentials: List<Credential>? = null,
    @SerialName(ETSI119475.PURPOSE_CLAIM) val purpose: List<MultiLangString>? = null,
    @SerialName(ETSI119475.INTENDED_USE_ID_CLAIM) val intendedUse: String? = null,
    @SerialName(ETSI119475.PUBLIC_BODY_CLAIM) val publicSectorBody: Boolean? = null,
    @SerialName(RFC7519.EXPIRES_AT_CLAIM) @Serializable(with = InstantEpochSecondsSerializer::class) val expiresAt: Instant? = null,
    @SerialName(ETSI119475.INTERMEDIARY_CLAIM) val intermediaries: Intermediary? = null,
) {
    init {
        require(serviceDescriptions.isNotEmpty())

        require(entitlements.isNotEmpty() && entitlements.distinct().size == entitlements.size)
        require(entitlements.any { it is Entitlement.WalletRelyingPartyEntitlement })

        if (entitlements.any { it is Entitlement.PaymentServiceProviderEntitlement }) {
            require(entitlements.any { it is Entitlement.PaymentServiceProviderSubEntitlement })
        }

        require(policies.isNotEmpty() && policies.distinct().size == policies.size)

        val attestationProviderEntitlements = setOf(
            Entitlement.WalletRelyingPartyEntitlement.PIDProvider,
            Entitlement.WalletRelyingPartyEntitlement.QEAAProvider,
            Entitlement.WalletRelyingPartyEntitlement.NonQEAAProvider,
        )
        if (entitlements.intersect(attestationProviderEntitlements).isNotEmpty()) {
            require(!providesAttestations.isNullOrEmpty())
        }

        if (null != credentials) {
            require(credentials.isNotEmpty())
        }

        if (null != purpose) {
            require(purpose.isNotEmpty())
        }
    }
}

@Serializable
@JvmInline
value class CountryCode(val code: String) {
    init {
        require(code.matches("[A-Z]{2}".toRegex()))
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

@Serializable(with = EntitlementSerializer::class)
sealed interface Entitlement {
    val uri: Uri

    enum class WalletRelyingPartyEntitlement(val oid: String, override val uri: Uri) : Entitlement {
        // General service provider
        ServiceProvider(ETSI119475.SERVICE_PROVIDER_ENTITLEMENT_OID, ETSI119475.SERVICE_PROVIDER_ENTITLEMENT_URI.toKmpUri()),

        // Qualified trust service provider issuing qualified electronic attestations of attributes
        QEAAProvider(ETSI119475.QEAA_PROVIDER_ENTITLEMENT_OID, ETSI119475.QEAA_PROVIDER_ENTITLEMENT_URI.toKmpUri()),

        // Trust service provider issuing non-qualified electronic attestations of attributes
        NonQEAAProvider(ETSI119475.NON_QEAA_PROVIDER_ENTITLEMENT_OID, ETSI119475.NON_QEAA_PROVIDER_ENTITLEMENT_URI.toKmpUri()),

        // Public sector body or its agent issuing electronic attestations of attributes from authentic sources
        PubEAAProvider(ETSI119475.PUB_EAA_PROVIDER_ENTITLEMENT_OID, ETSI119475.PUB_EAA_PROVIDER_ENTITLEMENT_URI.toKmpUri()),

        // Provider of person identification data
        PIDProvider(ETSI119475.PID_PROVIDER_ENTITLEMENT_OID, ETSI119475.PID_PROVIDER_ENTITLEMENT_URI.toKmpUri()),

        // QTSP issuing qualified certificates for electronic seals
        QCertForESealProvider(
            ETSI119475.QCERT_FOR_ESEAL_PROVIDER_ENTITLEMENT_OID,
            ETSI119475.QCERT_FOR_ESEAL_PROVIDER_ENTITLEMENT_URI.toKmpUri(),
        ),

        // QTSP issuing qualified certificates for electronic signatures
        QCertForESigProvider(
            ETSI119475.QCERT_FOR_ESIG_PROVIDER_ENTITLEMENT_OID,
            ETSI119475.QCERT_FOR_ESIG_PROVIDER_ENTITLEMENT_URI.toKmpUri(),
        ),

        // QTSP managing remote qualified electronic seal creation devices
        @Suppress("EnumEntryName")
        rQSealCDsProvider(ETSI119475.RQSEALCDS_PROVIDER_ENTITLEMENT_OID, ETSI119475.RQSEALCDS_PROVIDER_ENTITLEMENT_URI.toKmpUri()),

        // QTSP managing remote qualified electronic signature creation devices
        @Suppress("EnumEntryName")
        rQSigCDsProvider(ETSI119475.RQSIGCDS_PROVIDER_ENTITLEMENT_OID, ETSI119475.RQSIGCDS_PROVIDER_ENTITLEMENT_URI.toKmpUri()),

        // Non-qualified provider for remote signature/seal creation
        ESigESealCreationProvider(
            ETSI119475.ESIG_ESEAL_CREATION_PROVIDER_ENTITLEMENT_OID,
            ETSI119475.ESIG_ESEAL_CREATION_PROVIDER_ENTITLEMENT_URI.toKmpUri(),
        ),
    }

    enum class PaymentServiceProviderEntitlement(val role: String, val oid: String, override val uri: Uri) : Entitlement {
        // Account Servicing
        AccountingService(ETSI119495.ACCOUNTING_SERVICE_ROLE_NAME, ETSI119495.ACCOUNTING_SERVICE_ROLE_OID),

        // Payment Initiation
        PaymentInitiation(ETSI119495.PAYMENT_INITIATION_ROLE_NAME, ETSI119495.PAYMENT_INITIATION_ROLE_OID),

        // Account Information
        AccountingInformation(ETSI119495.ACCOUNT_INFORMATION_ROLE_NAME, ETSI119495.ACCOUNT_INFORMATION_ROLE_OID),

        // Issuing of Card-based payment instruments
        IssuingOfCardBasedPaymentInstruments(
            ETSI119495.ISSUING_OF_CARD_BASED_PAYMENT_INSTRUMENTS_ROLE_NAME,
            ETSI119495.ISSUING_OF_CARD_BASED_PAYMENT_INSTRUMENTS_ROLE_OID,
        ),

        // Central Bank
        CentralBank(ETSI119495.CENTRAL_BANK_ROLE_NAME, ETSI119495.CENTRAL_BANK_ROLE_OID),

        // Public Authority
        PublicAuthority(ETSI119495.PUBLIC_AUTHORITY_ROLE_NAME, ETSI119495.PUBLIC_AUTHORITY_ROLE_OID),

        // Unspecified
        Unspecified(ETSI119495.UNSPECIFIED_ROLE_NAME, ETSI119495.UNSPECIFIED_ROLE_OID),
        ;

        constructor(role: String, oid: String) : this(role, oid, "urn:oid:$oid".toKmpUri())
    }

    enum class PaymentServiceProviderSubEntitlement(override val uri: Uri) : Entitlement {
        // Account Servicing Payment Service Provider
        AccountServicingPaymentServiceProvider(ETSI119475.ACCOUNT_SERVICING_PAYMENT_SERVICE_PROVIDER_ENTITLEMENT_URI.toKmpUri()),

        // Payment Initiation Service Provider
        PaymentInitiationServiceProvider(ETSI119475.PAYMENT_INITIATION_SERVICE_PROVIDER_ENTITLEMENT_URI.toKmpUri()),

        // Account Information Service Provider
        AccountInformationServiceProvider(ETSI119475.ACCOUNT_INFORMATION_SERVICE_PROVIDER_ENTITLEMENT_URI.toKmpUri()),

        // Payment Service Provider issuing card-based payment instruments
        PaymentServiceProviderIssuingCardBasedPaymentInstruments(
            ETSI119475.PAYMENT_SERVICE_PROVIDER_ISSUING_CARD_BASED_PAYMENT_INSTRUMENTS_ENTITLEMENT_URI.toKmpUri(),
        ),

        // Unspecified Payment Service Provider
        UnspecifiedPaymentServiceProvider(ETSI119475.UNSPECIFIED_PAYMENT_SERVICE_PROVIDER_ENTITLEMENT_URI.toKmpUri()),
    }
}

object EntitlementSerializer : KSerializer<Entitlement> {
    override val descriptor: SerialDescriptor
        get() = PrimitiveSerialDescriptor("Entitlement", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Entitlement) {
        encoder.encodeString(value.uri.toString())
    }

    override fun deserialize(decoder: Decoder): Entitlement {
        val uri = decoder.decodeString().toKmpUri()
        return Entitlement.WalletRelyingPartyEntitlement.entries.firstOrNull { uri == it.uri }
            ?: Entitlement.PaymentServiceProviderEntitlement.entries.firstOrNull { uri == it.uri }
            ?: Entitlement.PaymentServiceProviderSubEntitlement.entries.firstOrNull { uri == it.uri }
            ?: throw IllegalArgumentException("Unknown Entitlement: $uri")
    }
}

@Serializable
data class SupervisoryAuthority(
    @Required @SerialName(ETSI119475.SUPERVISOR_AUTHORITY_EMAIL_CLAIM) val email: String,
    @Required @SerialName(ETSI119475.SUPERVISOR_AUTHORITY_PHONE_CLAIM) val phone: String,
    @Required @SerialName(ETSI119475.SUPERVISOR_AUTHORITY_URI_CLAIM) val uri: Url,
)

@Serializable
enum class CertificatePolicy(val oid: String) {

    @SerialName(ETSI119475.WALLET_RELYING_PARTY_CERTIFICATE_POLICY_OID)
    WalletRelyingParty(ETSI119475.WALLET_RELYING_PARTY_CERTIFICATE_POLICY_OID),
}

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
data class Credential(
    @Required @SerialName(ETSI119475.CREDENTIAL_FORMAT_CLAIM) val format: Format,
    @Required @SerialName(ETSI119475.CREDENTIAL_META_CLAIM) val meta: JsonObject,
    @SerialName(ETSI119475.CREDENTIAL_CLAIM_CLAIM) val claim: List<Claim>? = null,
) {
    init {
        if (null != claim) {
            require(claim.isNotEmpty())
        }
    }
}

val Credential.msoMDocMeta: DCQLMetaMsoMdocExtensions
    get() = jsonSupport.decodeFromJsonElement<DCQLMetaMsoMdocExtensions>(meta)

val Credential.sdJwtVcMeta: DCQLMetaSdJwtVcExtensions
    get() = jsonSupport.decodeFromJsonElement<DCQLMetaSdJwtVcExtensions>(meta)

@Serializable
data class Claim(
    @Required @SerialName(ETSI119475.CLAIM_PATH_CLAIM) val path: ClaimPath,
    @SerialName(ETSI119475.CLAIM_VALUES_CLAIM) val values: List<JsonPrimitive>? = null,
) {
    init {
        if (null != values) {
            require(values.isNotEmpty() && values.none { JsonNull == it })
        }
    }
}

@Serializable
data class Intermediary(
    @Required @SerialName(ETSI119475.INTERMEDIATE_IDENTIFIER_CLAIM) val identifier: String,
    @Required @SerialName(ETSI119475.INTERMEDIATE_NAME_CLAIM) val name: String,
)
