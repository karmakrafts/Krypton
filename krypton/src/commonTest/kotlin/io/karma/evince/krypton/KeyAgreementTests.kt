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

import io.karma.evince.krypton.parameters.DHKeypairGeneratorParameters
import io.karma.evince.krypton.parameters.ECKeypairGeneratorParameters
import io.karma.evince.krypton.parameters.ParameterGeneratorParameters
import io.kotest.core.spec.style.ShouldSpec
import kotlin.test.assertTrue

@OptIn(ExperimentalStdlibApi::class)
class KeyAgreementTests : ShouldSpec() {
    init {
        should("test ECDH") {
            DefaultAlgorithm.ECDH.generateKeypair(ECKeypairGeneratorParameters(
                EllipticCurve.PRIME192v1,
                arrayOf(Key.Usage.DERIVE)
            )).use { keypair ->
                DefaultAlgorithm.ECDH.generateKeypair(ECKeypairGeneratorParameters(
                    EllipticCurve.PRIME192v1,
                    arrayOf(Key.Usage.DERIVE)
                )).use { peerKeypair ->
                    val secret1 = DefaultAlgorithm.ECDH.computeSecret(keypair.private, peerKeypair.public)
                    val secret2 = DefaultAlgorithm.ECDH.computeSecret(peerKeypair.private, keypair.public)
                    assertTrue("The computed secrets are not the same (${secret1.toHexString()} != ${secret2.toHexString()})") {
                        secret1.contentEquals(secret2)
                    }
                }
            }
        }

        should("test DH") {
            val parameters = DefaultAlgorithm.DH.generateParameters<DHKeypairGeneratorParameters>(ParameterGeneratorParameters(1024U))
            DefaultAlgorithm.DH.generateKeypair(parameters).use { keypair ->
                DefaultAlgorithm.DH.generateKeypair(parameters).use { peerKeypair ->
                    val secret1 = DefaultAlgorithm.DH.computeSecret(keypair.private, peerKeypair.public)
                    val secret2 = DefaultAlgorithm.DH.computeSecret(peerKeypair.private, keypair.public)
                    assertTrue("The computed secrets are not the same (${secret1.toHexString()} != ${secret2.toHexString()})") {
                        secret1.contentEquals(secret2)
                    }
                }
            }
        }
    }
}
