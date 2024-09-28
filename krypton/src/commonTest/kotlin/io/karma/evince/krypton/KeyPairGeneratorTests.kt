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
import io.karma.evince.krypton.key.Key
import io.karma.evince.krypton.key.KeyPairGenerator
import io.karma.evince.krypton.key.KeyPairGeneratorParameters
import io.kotest.core.spec.style.ShouldSpec
import kotlin.test.assertEquals

class KeyPairGeneratorTests : ShouldSpec() {
    init {
        should("test RSA") {
            KeyPairGenerator(Algorithm.RSA, KeyPairGeneratorParameters(
                size = 2048,
                usages = arrayOf(Key.Usage.ENCRYPT, Key.Usage.DECRYPT)
            )).generate().use { keyPair ->
                assertEquals("RSA", keyPair.publicKey.algorithm)
                assertEquals(Key.Type.PUBLIC, keyPair.publicKey.type)
                assertEquals("RSA", keyPair.privateKey.algorithm)
                assertEquals(Key.Type.PRIVATE, keyPair.privateKey.type)
            }
        }
        
        should("test DH") {
            val parameters = ParameterGenerator(Algorithm.DH, ParameterGeneratorParameters(512)).generate()
            KeyPairGenerator(Algorithm.DH, parameters).generate().use { keyPair ->
                assertEquals("DH", keyPair.publicKey.algorithm)
                assertEquals(Key.Type.PUBLIC, keyPair.publicKey.type)
                assertEquals("DH", keyPair.privateKey.algorithm)
                assertEquals(Key.Type.PRIVATE, keyPair.privateKey.type)
            }
        }
        
        should("test ECDH") {
            KeyPairGenerator(Algorithm.ECDH, ECKeyPairGeneratorParameters(
                curve = EllipticCurve.P521,
                usages = arrayOf(Key.Usage.DERIVE)
            )).generate()
                .use { keyPair ->
                    assertEquals("ECDH", keyPair.publicKey.algorithm)
                    assertEquals(Key.Type.PUBLIC, keyPair.publicKey.type)
                    assertEquals("ECDH", keyPair.privateKey.algorithm)
                    assertEquals(Key.Type.PRIVATE, keyPair.privateKey.type)
                }
        }
    }
}
