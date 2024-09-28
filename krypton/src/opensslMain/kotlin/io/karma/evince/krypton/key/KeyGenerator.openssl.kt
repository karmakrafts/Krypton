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

package io.karma.evince.krypton.key

import io.karma.evince.krypton.Algorithm
import io.karma.evince.krypton.utils.ErrorHelper
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import io.karma.evince.krypton.internal.openssl.*

/** @suppress **/
actual class KeyGenerator actual constructor(
    private val algorithm: String,
    private val parameters: KeyGeneratorParameters
) {
    actual constructor(algorithm: Algorithm, parameters: KeyGeneratorParameters) :
            this(algorithm.validOrError(Algorithm.Scope.KEY_GENERATOR).toString(), parameters)
    
    actual suspend fun generate(): Key {
        return Key(
            type = Key.Type.SYMMETRIC,
            usages = arrayOf(),
            algorithm = algorithm,
            data = requireNotNull(BIO_new(BIO_s_secmem())).let { data ->
                val parameterSize = parameters.size
                ByteArray(parameterSize).usePinned { dataPtr ->
                    if (RAND_bytes(dataPtr.addressOf(0).reinterpret(), parameters.size) != 1)
                        throw RuntimeException(
                            message = "Unable to generate random data for key",
                            cause = ErrorHelper.createOpenSSLException()
                        )
                    BIO_write(data, dataPtr.addressOf(0), parameterSize)
                }
                data
            }
        )
    }
}
