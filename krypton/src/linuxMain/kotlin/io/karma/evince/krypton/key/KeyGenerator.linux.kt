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
import libssl.BIO_new
import libssl.BIO_s_secmem
import libssl.BIO_write
import libssl.RAND_bytes

actual class KeyGenerator actual constructor(
    private val algorithm: String,
    private val parameter: KeyGeneratorParameter
) {

    actual constructor(algorithm: Algorithm, parameter: KeyGeneratorParameter) : this(algorithm.toString(), parameter)

    actual fun generate(): Key {
        return Key(KeyType.SYMMETRIC, algorithm, requireNotNull(BIO_new(BIO_s_secmem())).apply {
            val parameterSize = parameter.size
            val data = BIO_new(BIO_s_secmem())
            ByteArray(parameterSize).usePinned { dataPtr ->
                if (RAND_bytes(dataPtr.addressOf(0).reinterpret(), parameter.size) != 1)
                    throw RuntimeException(
                        "Unable to generate random data for key",
                        ErrorHelper.createOpenSSLException()
                    )
                BIO_write(data, dataPtr.addressOf(0), parameterSize)
            }
        })
    }

}
