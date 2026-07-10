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

object ETSI119475 {
    // JWT Type
    const val WALLET_RELYING_PARTY_REGISTRATION_CERTIFICATE_TYPE = "rc-wrp+jwt"

    // Entitlements
    const val SERVICE_PROVIDER_ENTITLEMENT_URI = "https://uri.etsi.org/19475/Entitlement/Service_Provider"
    const val SERVICE_PROVIDER_ENTITLEMENT_OID = "0.4.0.19475.1.1"
    const val QEAA_PROVIDER_ENTITLEMENT_URI = "https://uri.etsi.org/19475/Entitlement/QEAA_Provider"
    const val QEAA_PROVIDER_ENTITLEMENT_OID = "0.4.0.19475.1.2"
    const val NON_QEAA_PROVIDER_ENTITLEMENT_URI = "https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider"
    const val NON_QEAA_PROVIDER_ENTITLEMENT_OID = "0.4.0.19475.1.3"
    const val PUB_EAA_PROVIDER_ENTITLEMENT_URI = "https://uri.etsi.org/19475/Entitlement/PUB_EAA_Provider"
    const val PUB_EAA_PROVIDER_ENTITLEMENT_OID = "0.4.0.19475.1.4"
    const val PID_PROVIDER_ENTITLEMENT_URI = "https://uri.etsi.org/19475/Entitlement/PID_Provider"
    const val PID_PROVIDER_ENTITLEMENT_OID = "0.4.0.19475.1.5"
    const val QCERT_FOR_ESEAL_PROVIDER_ENTITLEMENT_URI = "https://uri.etsi.org/19475/Entitlement/QCert_for_ESeal_Provider"
    const val QCERT_FOR_ESEAL_PROVIDER_ENTITLEMENT_OID = "0.4.0.19475.1.6"
    const val QCERT_FOR_ESIG_PROVIDER_ENTITLEMENT_URI = "https://uri.etsi.org/19475/Entitlement/QCert_for_ESig_Provider"
    const val QCERT_FOR_ESIG_PROVIDER_ENTITLEMENT_OID = "0.4.0.19475.1.7"
    const val RQSEALCDS_PROVIDER_ENTITLEMENT_URI = "https://uri.etsi.org/19475/Entitlement/rQSealCDs_Provider"
    const val RQSEALCDS_PROVIDER_ENTITLEMENT_OID = "0.4.0.19475.1.8"
    const val RQSIGCDS_PROVIDER_ENTITLEMENT_URI = "https://uri.etsi.org/19475/Entitlement/rQSigCDs_Provider"
    const val RQSIGCDS_PROVIDER_ENTITLEMENT_OID = "0.4.0.19475.1.9"
    const val ESIG_ESEAL_CREATION_PROVIDER_ENTITLEMENT_URI = "https://uri.etsi.org/19475/Entitlement/ESig_ESeal_Creation_Provider"
    const val ESIG_ESEAL_CREATION_PROVIDER_ENTITLEMENT_OID = "0.4.0.19475.1.10"
    const val ACCOUNT_SERVICING_PAYMENT_SERVICE_PROVIDER_ENTITLEMENT_URI = "https://uri.etsi.org/19475/SubEntitlement/psp/psp-as"
    const val PAYMENT_INITIATION_SERVICE_PROVIDER_ENTITLEMENT_URI = "https://uri.etsi.org/19475/SubEntitlement/psp/psp-pi"
    const val ACCOUNT_INFORMATION_SERVICE_PROVIDER_ENTITLEMENT_URI = "https://uri.etsi.org/19475/SubEntitlement/psp/psp-ai"
    const val PAYMENT_SERVICE_PROVIDER_ISSUING_CARD_BASED_PAYMENT_INSTRUMENTS_ENTITLEMENT_URI =
        "https://uri.etsi.org/19475/SubEntitlement/psp/psp-ic"
    const val UNSPECIFIED_PAYMENT_SERVICE_PROVIDER_ENTITLEMENT_URI = "https://uri.etsi.org/19475/SubEntitlement/psp/unspecified"

    // Certificate Policies
    const val WALLET_RELYING_PARTY_CERTIFICATE_POLICY_OID = "0.4.0.19475.3.1"

    // Claims
    const val TRADE_NAME_CLAIM = "name"
    const val LEGAL_NAME_CLAIM = "sub_ln"
    const val GIVEN_NAME_CLAIM = "sub_gn"
    const val FAMILY_NAME_CLAIM = "sub_fn"
    const val IDENTIFIER_CLAIM = "sub"
    const val COUNTRY_CLAIM = "country"
    const val REGISTRY_URI_CLAIM = "registry_uri"
    const val SERVICE_DESCRIPTION_CLAIM = "srv_description"
    const val ENTITLEMENTS_CLAIM = "entitlements"
    const val PRIVACY_POLICY_CLAIM = "privacy_policy"
    const val INFO_URI_CLAIM = "info_uri"
    const val SUPPORT_URI_CLAIM = "support_uri"
    const val SUPERVISORY_AUTHORITY_CLAIM = "supervisory_authority"
    const val POLICY_ID_CLAIM = "policy_id"
    const val CERTIFICATE_POLICY_CLAIM = "certificate_policy"
    const val PROVIDES_ATTESTATIONS_CLAIM = "provides_attestations"
    const val CREDENTIALS_CLAIM = "credentials"
    const val PURPOSE_CLAIM = "purpose"
    const val INTENDED_USE_ID_CLAIM = "intended_use_id"
    const val PUBLIC_BODY_CLAIM = "public_body"
    const val INTERMEDIARY_CLAIM = "intermediary"

    const val MULTILANG_STRING_LANG_CLAIM = "lang"
    const val MULTILANG_STRING_VALUE_CLAIM = "value"

    const val SUPERVISOR_AUTHORITY_EMAIL_CLAIM = "email"
    const val SUPERVISOR_AUTHORITY_PHONE_CLAIM = "phone"
    const val SUPERVISOR_AUTHORITY_URI_CLAIM = "uri"

    const val CREDENTIAL_FORMAT_CLAIM = "format"
    const val CREDENTIAL_META_CLAIM = "meta"
    const val CREDENTIAL_CLAIM_CLAIM = "claim"

    const val CLAIM_PATH_CLAIM = "path"
    const val CLAIM_VALUES_CLAIM = "values"

    const val INTERMEDIATE_IDENTIFIER_CLAIM = "sub"
    const val INTERMEDIATE_NAME_CLAIM = "name"
}
