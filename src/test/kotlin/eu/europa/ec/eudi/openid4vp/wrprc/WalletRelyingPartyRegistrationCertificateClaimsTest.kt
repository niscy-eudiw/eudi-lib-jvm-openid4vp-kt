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

import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import kotlin.test.Test

class WalletRelyingPartyRegistrationCertificateClaimsTest {

    private val serialized =
        """
            {
                "name": "Example Company",
                "sub_ln": "Example Company GmbH",
                "sub": "LEIXG-529900T8BM49AURSDO55",
                "country": "DE",
                "registry_uri": "https://registrar.com",
                "srv_description": [
                    {
                        "lang": "en-US",
                        "value": "Awesome Service by Example Company"
                    },
                    {
                        "lang": "de-DE",
                        "value": "Super Dienst von Example Company"
                    }
                ],
                "entitlements": [
                    "https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider"
                ],
                "privacy_policy": "https://example.com/privacy-policy",
                "info_uri": "https://example.com/info",
                "support_uri": "https://example.com/support",
                "supervisory_authority": {
                    "email": "supervisory@dpa.com",
                    "phone": "+49 123 4567890",
                    "uri": "https://dpa.com/supervisory-authority"
                },
                "policy_id": [
                    "0.4.0.19475.3.1"
                ],
                "certificate_policy": "https://registrar.com/certificate-policy",
                "iat": 1683000000,
                "status": {
                    "status_list": {
                        "idx": 0,
                        "uri": "https://example.com/statuslists/1"
                    }
                },
                "purpose": [
                    {
                        "lang": "en-US",
                        "value": "Required for checking the minimum age"
                    },
                    {
                        "lang": "de-DE",
                        "value": "Benötigt für die Überprüfung des Mindestalters"
                    }
                ],
                "credentials": [
                    {
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": [
                                "urn:eudi:pid:de:1"
                            ]
                        },
                        "claim": [
                            {
                                "path": [
                                    "age_equal_or_over",
                                    "18"
                                ]
                            }
                        ]
                    },
                    {
                        "format": "mso_mdoc",
                        "meta": {
                            "doctype_value": "eu.europa.ec.eudi.pid.1"
                        },
                        "claim": [
                            {
                                "path": [
                                    "eu.europa.ec.eudi.pid.1",
                                    "age_over_18"
                                ]
                            }
                        ]
                    }
                ],
                "provides_attestations": [
                    {
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": [
                                "https://example.com/attestations/age_over_18"
                            ]
                        }
                    }
                ],
                "intermediary": {
                    "sub": "LEIXG-INTERMEDIARY-1234567890",
                    "name": "Intermediary Services Ltd."
                }
            }
        """.trimIndent()

    @Test
    fun `parses successfully`() {
        val deserialized = jsonSupport.decodeFromString<WalletRelyingPartyRegistrationCertificateClaims>(serialized)
        println(deserialized)
    }
}
