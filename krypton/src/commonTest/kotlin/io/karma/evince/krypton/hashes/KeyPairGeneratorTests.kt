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

import com.ionspin.kotlin.bignum.integer.BigInteger
import io.karma.evince.krypton.Algorithm
import io.karma.evince.krypton.annotations.UncheckedKryptonAPI
import io.karma.evince.krypton.ec.EllipticCurveParameters
import io.karma.evince.krypton.ec.curve
import io.karma.evince.krypton.key.*
import io.kotest.core.spec.style.ShouldSpec
import kotlin.test.assertEquals

@OptIn(UncheckedKryptonAPI::class)
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

        should("test prime curves") {
            curve {
                name = "Test"
                field = EllipticCurveParameters.Field.Fp(BigInteger.parseString("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16))
                a = BigInteger.parseString("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16)
                b = BigInteger.parseString("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
                order = BigInteger.parseString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
                generatorPoint = Pair(
                    BigInteger.parseString("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
                    BigInteger.parseString("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16))
            }.use {
                KeyPairGenerator(Algorithm.ECDH, ECKeyPairGeneratorParameter(it)).use { gen ->
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
}
