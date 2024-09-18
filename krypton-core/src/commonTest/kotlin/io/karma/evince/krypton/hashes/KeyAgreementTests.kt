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
import io.karma.evince.krypton.ec.EllipticCurve
import io.karma.evince.krypton.key.*
import io.kotest.core.spec.style.ShouldSpec
import kotlin.test.assertTrue

class KeyAgreementTests : ShouldSpec() {
    init {
        should("test ECDH agreement") {
            KeyPairGenerator(Algorithm.ECDH, ECKeyPairGeneratorParameter(EllipticCurve.PRIME256V1)).use { gen ->
                gen.generate().use { kp1 ->
                    gen.generate().use { kp2 ->
                        val secret1 = KeyAgreement(Algorithm.ECDH, kp1.privateKey)
                            .use { it.generateSecret(kp2.publicKey) }
                        val secret2 = KeyAgreement(Algorithm.ECDH, kp2.privateKey)
                            .use { it.generateSecret(kp1.publicKey) }
                        assertTrue(secret1.contentEquals(secret2))
                    }
                }
            }
        }
        
        should("test DH agreement") {
            KeyPairGenerator(Algorithm.DH, KeyPairGeneratorParameter(1024)).use { gen ->
                gen.generate().use { kp1 ->
                    gen.generate().use { kp2 ->
                        val secret1 = KeyAgreement(Algorithm.DH, kp1.privateKey)
                            .use { it.generateSecret(kp2.publicKey) }
                        val secret2 = KeyAgreement(Algorithm.DH, kp2.privateKey)
                            .use { it.generateSecret(kp1.publicKey) }
                        assertTrue(secret1.contentEquals(secret2))
                    }
                }
            }
        }
        
        should("test DH agreement with custom parameters") {
            KeyPairGenerator(
                Algorithm.DH,
                DHKeyPairGeneratorParameter(
                    BigInteger.parseString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16),
                    BigInteger.fromInt(2),
                    4096
                )
            ).use { gen ->
                gen.generate().use { kp1 ->
                    gen.generate().use { kp2 ->
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
}
