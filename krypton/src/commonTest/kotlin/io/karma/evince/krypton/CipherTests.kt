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
import io.karma.evince.krypton.key.KeyGenerator
import io.karma.evince.krypton.key.KeyGeneratorParameters
import io.karma.evince.krypton.key.KeyPairGenerator
import io.karma.evince.krypton.key.KeyPairGeneratorParameters
import io.kotest.core.spec.style.ShouldSpec
import kotlin.test.assertEquals

class CipherTests : ShouldSpec() {
    init {
        should("test AES-CBC") {
            val key = KeyGenerator(Algorithm.AES, KeyGeneratorParameters(128)).generate()
            val string = "This is a secret".encodeToByteArray()
            val enc = Cipher(Algorithm.AES, key, CipherParameters(Cipher.Mode.ENCRYPT)).process(string)
            val dec = Cipher(Algorithm.AES, key, CipherParameters(Cipher.Mode.DECRYPT)).process(enc)
            assertEquals("This is a secret", dec.decodeToString())
        }

        should("test AES-GCM") {
            val key = KeyGenerator(Algorithm.AES, KeyGeneratorParameters(128)).generate()
            val string = "This is a secret".encodeToByteArray()

            val enc = Cipher(Algorithm.AES, key, GCMCipherParameters(Cipher.Mode.ENCRYPT, 2)).process(string, byteArrayOf(0x1, 0x2))
            val dec = Cipher(Algorithm.AES, key, GCMCipherParameters(Cipher.Mode.DECRYPT, 2)).process(enc, byteArrayOf(0x1, 0x2))
            assertEquals("This is a secret", dec.decodeToString())
        }

        should("test AES-CTR") {
            val key = KeyGenerator(Algorithm.AES, KeyGeneratorParameters(128)).generate()
            val string = "This is a secret".encodeToByteArray()

            val enc = Cipher(Algorithm.AES, key, GCMCipherParameters(Cipher.Mode.ENCRYPT, 2)).process(string)
            val dec = Cipher(Algorithm.AES, key, GCMCipherParameters(Cipher.Mode.DECRYPT, 2)).process(enc)
            assertEquals("This is a secret", dec.decodeToString())
        }
        
        should("test RSA") {
            KeyPairGenerator(
                algorithm = Algorithm.RSA,
                parameters = KeyPairGeneratorParameters(2048, arrayOf(Key.Usage.ENCRYPT, Key.Usage.DECRYPT))
            ).generate().use { keyPair ->
                val string = "This is a secret".encodeToByteArray()
                val enc = Cipher(Algorithm.RSA, keyPair.publicKey, CipherParameters(Cipher.Mode.ENCRYPT))
                    .process(string)
                val dec = Cipher(Algorithm.RSA, keyPair.privateKey, CipherParameters(Cipher.Mode.DECRYPT))
                    .process(enc)
                assertEquals("This is a secret", dec.decodeToString())
            }
        }
    }
}
