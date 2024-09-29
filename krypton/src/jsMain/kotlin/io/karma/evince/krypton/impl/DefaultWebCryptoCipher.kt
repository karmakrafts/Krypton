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

package io.karma.evince.krypton.impl

import io.karma.evince.krypton.Algorithm
import io.karma.evince.krypton.Cipher
import io.karma.evince.krypton.DefaultAlgorithm
import io.karma.evince.krypton.parameters.CipherParameters
import io.karma.evince.krypton.parameters.GCMCipherParameters
import js.typedarrays.Uint8Array
import js.typedarrays.asInt8Array
import js.typedarrays.toUint8Array
import web.crypto.AesCbcParams
import web.crypto.AesGcmParams
import web.crypto.crypto

internal typealias WebCryptoAlgorithm = web.crypto.Algorithm

class DefaultWebCryptoCipher(private val algorithm: Algorithm, private val parameters: CipherParameters) : Cipher {
    override suspend fun run(input: ByteArray, aad: ByteArray?): ByteArray = Uint8Array(
        when (parameters.mode) {
            Cipher.Mode.ENCRYPT -> crypto.subtle.encrypt(getAlgorithm(aad), parameters.key.internal, input.asInt8Array())
            Cipher.Mode.DECRYPT -> crypto.subtle.decrypt(getAlgorithm(aad), parameters.key.internal, input.asInt8Array())
        }
    ).toByteArray()

    private fun getAlgorithm(aad: ByteArray?): WebCryptoAlgorithm = when (algorithm) { // TODO: Implement other block modes and algorithms
        DefaultAlgorithm.AES -> when (val blockMode = parameters.blockMode ?: algorithm.defaultBlockMode) {
            Algorithm.BlockMode.CBC -> AesCbcParams.invoke("AES-CBC", ByteArray(16) { 0 }.toUint8Array())
            Algorithm.BlockMode.GCM -> (parameters as GCMCipherParameters).let { params ->
                AesGcmParams.invoke(
                    name = "AES-GCM",
                    tagLength = params.tagLength.toShort(),
                    iv = params.iv.toUint8Array(),
                    additionalData = aad?.toUint8Array()
                )
            }
            else -> throw IllegalArgumentException("Block mode '$blockMode' for '${algorithm.literal}' is not supported")
        }

        else -> throw IllegalArgumentException("Algorithm '${algorithm.literal}' is not supported")
    }
}

