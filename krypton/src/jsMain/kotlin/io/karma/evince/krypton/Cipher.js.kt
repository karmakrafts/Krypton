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

import io.karma.evince.krypton.annotations.UncheckedKryptonAPI
import io.karma.evince.krypton.key.Key
import js.buffer.ArrayBuffer
import js.buffer.BufferSource
import js.typedarrays.Uint8Array
import js.typedarrays.asInt8Array
import js.typedarrays.toUint8Array
import web.crypto.AesCbcParams
import web.crypto.AesGcmParams
import web.crypto.CryptoKey
import web.crypto.crypto

private typealias WebCryptoAlgorithm = web.crypto.Algorithm

/**
 * @author Cedric Hammes
 * @param  28/09/2024
 * @suppress
 */
actual class Cipher actual constructor(
    private val algorithm: String,
    private val key: Key,
    private val parameters: CipherParameters
) {
    @UncheckedKryptonAPI
    actual constructor(algorithm: Algorithm, key: Key, parameters: CipherParameters) :
            this(algorithm.validOrError(Algorithm.Scope.CIPHER).toString(), key, parameters)

    actual suspend fun process(data: ByteArray, aad: ByteArray?): ByteArray {
        val iv = parameters.tryIV(algorithm)?.toUint8Array()
        return Uint8Array(
            parameters.mode.operation(
                when (algorithm) {
                    "AES" -> {
                        when (parameters.blockMode?: Algorithm.AES.defaultBlockMode) {
                            BlockMode.CBC -> AesCbcParams.invoke("AES-CBC", requireNotNull(iv))
                            BlockMode.GCM -> AesGcmParams.invoke(
                                name = "AES-GCM",
                                tagLength = (parameters as? GCMCipherParameters)?.tagLen?.toShort(),
                                iv = requireNotNull(iv),
                                additionalData = aad?.asInt8Array()
                            )
                            // TODO: Add support for CTR and the other modes
                            else -> WebCryptoAlgorithm.invoke(algorithm)
                        }
                    }
                    else -> WebCryptoAlgorithm.invoke(algorithm)
                },
                key.internal,
                data.toUint8Array()
            )
        ).toByteArray()
    }

    actual enum class Mode(internal val operation: suspend (WebCryptoAlgorithm, CryptoKey, BufferSource) -> ArrayBuffer) {
        ENCRYPT(crypto.subtle::encrypt),
        DECRYPT(crypto.subtle::decrypt)
    }

}
