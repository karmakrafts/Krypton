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

import io.karma.evince.krypton.parameters.KeypairGeneratorParameters
import io.karma.evince.krypton.parameters.SignatureParameters
import io.kotest.core.spec.style.ShouldSpec
import kotlin.test.assertTrue

class SignatureTests : ShouldSpec() {
    init {
        should("test SHA-256 with RSA") {
            val usages = arrayOf(Key.Usage.SIGN, Key.Usage.VERIFY)
            DefaultAlgorithm.RSA.generateKeypair(KeypairGeneratorParameters(2048U, usages, padding = Algorithm.Padding.PKCS1))
                .use { keypair ->
                    val signer = DefaultAlgorithm.RSA.createSignature(SignatureParameters(keypair.private, DefaultAlgorithm.SHA256))
                    val signature = signer.sign("Test".encodeToByteArray())
                    val verifier = DefaultAlgorithm.RSA.createSignature(SignatureParameters(keypair.public, DefaultAlgorithm.SHA256))
                    val isValid = verifier.verify(signature, "Test".encodeToByteArray())
                    assertTrue(message = "Signature os 'Test' is invalid") { isValid }
                }
        }
    }
}
