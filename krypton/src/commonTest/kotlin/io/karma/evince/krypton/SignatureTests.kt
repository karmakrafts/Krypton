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

import io.karma.evince.krypton.key.Key
import io.karma.evince.krypton.key.KeyPairGenerator
import io.karma.evince.krypton.key.KeyPairGeneratorParameters
import io.kotest.core.spec.style.ShouldSpec
import kotlin.test.assertTrue

class SignatureTests : ShouldSpec() {
    init {
        should("test SHA3-256 with RSA") {
            KeyPairGenerator(Algorithm.RSA, KeyPairGeneratorParameters(
                size = 2048,
                usages = arrayOf(Key.Usage.SIGN, Key.Usage.VERIFY)
            )).generate().use { keyPair ->
                val signature = Signature(
                    key = keyPair.privateKey,
                    algorithm = Algorithm.RSA,
                    parameters = SignatureParameters(Algorithm.SHA3_256, SignatureParameters.EnumType.SIGN)
                ).sign("Test".encodeToByteArray())
                assertTrue(
                    Signature(
                        key = keyPair.publicKey,
                        algorithm = Algorithm.RSA,
                        parameters = SignatureParameters(Algorithm.SHA3_256, SignatureParameters.EnumType.VERIFY)
                    ).verify(signature, "Test".encodeToByteArray())
                )
            }
        }
    }
}
