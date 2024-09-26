/*
 * Copyright 2024 Karma Krafts & associates
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

package io.karma.evince.krypton

import io.karma.evince.krypton.ec.EllipticCurve
import io.karma.evince.krypton.key.ECKeyPairGeneratorParameters
import io.karma.evince.krypton.key.KeyAgreement
import io.karma.evince.krypton.key.KeyPairGenerator
import io.kotest.core.spec.style.ShouldSpec
import kotlin.test.assertTrue

class KeyAgreementTests : ShouldSpec() {
    init {
        should("test ECDH agreement") {
            val generator = KeyPairGenerator(Algorithm.ECDH, ECKeyPairGeneratorParameters(EllipticCurve.PRIME256V1))
            generator.generate().use { kp1 ->
                generator.generate().use { kp2 ->
                    val secret1 = KeyAgreement(Algorithm.ECDH, kp1.privateKey)
                        .use { it.generateSecret(kp2.publicKey) }
                    val secret2 = KeyAgreement(Algorithm.ECDH, kp2.privateKey)
                        .use { it.generateSecret(kp1.publicKey) }
                    assertTrue(secret1.contentEquals(secret2))
                }
            }
        }
        
        should("test DH agreement") {
            val parameters = ParameterGenerator(Algorithm.DH, ParameterGeneratorParameters(512)).use { it.generate() }
            val generator = KeyPairGenerator(Algorithm.DH, parameters)
            generator.generate().use { kp1 ->
                generator.generate().use { kp2 ->
                    val secret1 = KeyAgreement(Algorithm.DH, kp1.privateKey)
                        .use { it.generateSecret(kp2.publicKey) }
                    val secret2 = KeyAgreement(Algorithm.DH, kp2.privateKey)
                        .use { it.generateSecret(kp1.publicKey) }
                    assertTrue(secret1.contentEquals(secret2))
                }
            }
        }
    }
}
