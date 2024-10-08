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

package io.karma.evince.krypton.utils

import kotlinx.cinterop.addressOf
import kotlinx.cinterop.toKString
import kotlinx.cinterop.usePinned
import io.karma.evince.krypton.internal.openssl.ERR_error_string
import io.karma.evince.krypton.internal.openssl.ERR_get_error

/** @suppress **/
object ErrorHelper {
    fun createOpenSSLException(): Exception = getOpenSSLErrors().let { errors ->
        throw when {
            errors.isEmpty() -> OpenSSLException("No OpenSSL errors captured (ERR_get_error() == 0)")
            else -> OpenSSLException(errors.joinToString(", "))
        }
    }
    
    private fun getOpenSSLErrors(): List<String> {
        val errorList = mutableListOf<String>()
        var error = ERR_get_error()
        while (error.toLong() != 0L) {
            val errorBuffer = ByteArray(120)
            errorBuffer.usePinned { bufferPtr -> ERR_error_string(error, bufferPtr.addressOf(0)) }
            errorList.add(errorBuffer.toKString())
            error = ERR_get_error()
        }
        return errorList
    }
    
    /** @suppress **/
    internal class OpenSSLException(message: String) : RuntimeException(message)
}
