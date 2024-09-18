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

package io.karma.evince.krypton.hashes

import io.karma.evince.krypton.Algorithm
import io.karma.evince.krypton.ec.EllipticCurve
import io.karma.evince.krypton.key.*
import io.kotest.core.spec.style.ShouldSpec
import kotlin.test.assertEquals

class KeyPairGeneratorTests : ShouldSpec() {
    init {
        should("test RSA") {
            KeyPairGenerator(Algorithm.RSA, KeyPairGeneratorParameter(2048)).use { gen ->
                gen.generate().use { keyPair ->
                    assertEquals("RSA", keyPair.publicKey.algorithm)
                    assertEquals(KeyType.PUBLIC, keyPair.publicKey.type)
                    assertEquals("RSA", keyPair.privateKey.algorithm)
                    assertEquals(KeyType.PRIVATE, keyPair.privateKey.type)
                }
            }
        }

        should("test DH") {
            KeyPairGenerator(Algorithm.DH, KeyPairGeneratorParameter(4096)).use { gen ->
                gen.generate().use { keyPair ->
                    assertEquals("DH", keyPair.publicKey.algorithm)
                    assertEquals(KeyType.PUBLIC, keyPair.publicKey.type)
                    assertEquals("DH", keyPair.privateKey.algorithm)
                    assertEquals(KeyType.PRIVATE, keyPair.privateKey.type)
                }
            }
        }

        should("test ECDH") {
            KeyPairGenerator(Algorithm.ECDH, ECKeyPairGeneratorParameter(EllipticCurve.PRIME192V1)).use { gen ->
                gen.generate().use { keyPair ->
                    assertEquals("ECDH", keyPair.publicKey.algorithm)
                    assertEquals(KeyType.PUBLIC, keyPair.publicKey.type)
                    assertEquals("ECDH", keyPair.privateKey.algorithm)
                    assertEquals(KeyType.PRIVATE, keyPair.privateKey.type)
                }
            }
        }
    }
}
