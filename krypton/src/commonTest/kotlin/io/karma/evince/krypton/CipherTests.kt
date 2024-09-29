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

import io.karma.evince.krypton.parameters.CBCCipherParameters
import io.karma.evince.krypton.parameters.CipherParameters
import io.karma.evince.krypton.parameters.KeyGeneratorParameters
import io.karma.evince.krypton.parameters.KeypairGeneratorParameters
import io.kotest.core.spec.style.ShouldSpec
import kotlin.test.assertEquals

class CipherTests : ShouldSpec() {
    init {
        should("test AES-CBC") {
            DefaultAlgorithm.AES.generateKey(KeyGeneratorParameters(128U, arrayOf(Key.Usage.ENCRYPT, Key.Usage.DECRYPT))).use { key ->
                val text = "Test".encodeToByteArray()
                val encrypted = DefaultAlgorithm.AES.createCipher(CBCCipherParameters(
                    padding = Algorithm.Padding.PKCS5,
                    blockMode = Algorithm.BlockMode.CBC,
                    mode = Cipher.Mode.ENCRYPT,
                    key = key,
                    iv = ByteArray(16) { 0 }
                )).run(text)
                val decrypted = DefaultAlgorithm.AES.createCipher(CBCCipherParameters(
                    padding = Algorithm.Padding.PKCS5,
                    blockMode = Algorithm.BlockMode.CBC,
                    mode = Cipher.Mode.DECRYPT,
                    key = key,
                    iv = ByteArray(16) { 0 }
                )).run(encrypted)
                assertEquals("Test", decrypted.decodeToString())
            }
        }
        should("test RSA") {
            DefaultAlgorithm.RSA.generateKeypair(KeypairGeneratorParameters(2048U, arrayOf(Key.Usage.ENCRYPT, Key.Usage.DECRYPT)))
                .use { keypair ->
                    val encrypted = DefaultAlgorithm.RSA.createCipher(CipherParameters(
                        padding = Algorithm.Padding.OAEP_SHA1,
                        mode = Cipher.Mode.ENCRYPT,
                        key = keypair.public
                    )).run("Test".encodeToByteArray())
                    val decrypted = DefaultAlgorithm.RSA.createCipher(CipherParameters(
                        padding = Algorithm.Padding.OAEP_SHA1,
                        mode = Cipher.Mode.DECRYPT,
                        key = keypair.private
                    )).run(encrypted)
                    assertEquals("Test", decrypted.decodeToString())

                }
        }
    }
}
