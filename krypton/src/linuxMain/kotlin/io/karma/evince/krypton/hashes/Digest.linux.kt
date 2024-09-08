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

package io.karma.evince.krypton.hashes

import io.karma.evince.krypton.utils.ErrorHelper
import kotlinx.cinterop.*
import libssl.*

@OptIn(ExperimentalForeignApi::class)
actual class Digest actual constructor(string: String, private val size: Int) : AutoCloseable {
    private val context = requireNotNull(EVP_MD_CTX_new())

    actual constructor(type: DigestType, size: Int) : this(type.toString(), size)

    init {
        if (size == 0) {
            throw IllegalArgumentException("The size of the '$string' digest is not set, please set a size manually")
        }

        if (EVP_DigestInit_ex(context, EVP_get_digestbyname(string), null) != 1) {
            EVP_MD_CTX_free(context)
            throw RuntimeException("Unable to initialize digest for '$string'", ErrorHelper.createOpenSSLException())
        }
    }

    actual fun hash(value: ByteArray): ByteArray {
        value.usePinned { valuePtr ->
            if (EVP_DigestUpdate(context, valuePtr.addressOf(0), value.size.toULong()) != 1)
                throw RuntimeException("Unable to update digest", ErrorHelper.createOpenSSLException())
        }

        val output = ByteArray(size)
        memScoped {
            val size = alloc<UIntVar>()
            size.value = output.size.toUInt()
            output.usePinned { outputPtr ->
                if (EVP_DigestFinal_ex(context, outputPtr.addressOf(0).reinterpret(), size.ptr) != 1)
                    throw RuntimeException("Unable to final digest", ErrorHelper.createOpenSSLException())
            }
        }
        return output
    }

    actual override fun close() {
        EVP_MD_CTX_free(context)
    }

}
