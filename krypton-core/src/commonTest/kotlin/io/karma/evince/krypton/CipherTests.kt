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

import io.karma.evince.krypton.key.KeyGenerator
import io.karma.evince.krypton.key.KeyGeneratorParameters
import io.karma.evince.krypton.key.KeyPairGenerator
import io.karma.evince.krypton.key.KeyPairGeneratorParameters
import io.kotest.core.spec.style.ShouldSpec
import kotlin.test.assertEquals

class CipherTests : ShouldSpec() {
    init {
        should("test AES") {
            val key = KeyGenerator(Algorithm.AES, KeyGeneratorParameters(128)).generate()
            val string = "This is a secret".encodeToByteArray()
            val enc = Cipher(Algorithm.AES, key, CipherParameters(Cipher.Mode.ENCRYPT)).use { it.process(string) }
            val dec = Cipher(Algorithm.AES, key, CipherParameters(Cipher.Mode.DECRYPT)).use { it.process(enc) }
            assertEquals("This is a secret", dec.decodeToString())
        }
        
        should("test RSA") {
            KeyPairGenerator(Algorithm.RSA, KeyPairGeneratorParameters(2048)).generate().use { keyPair ->
                val string = "This is a secret".encodeToByteArray()
                val enc = Cipher(Algorithm.RSA, keyPair.publicKey, CipherParameters(Cipher.Mode.ENCRYPT))
                    .use { it.process(string) }
                val dec = Cipher(Algorithm.RSA, keyPair.privateKey, CipherParameters(Cipher.Mode.DECRYPT))
                    .use { it.process(enc) }
                assertEquals("This is a secret", dec.decodeToString())
            }
        }
    }
}
