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

import io.karma.evince.krypton.internal.openssl.ERR_error_string
import io.karma.evince.krypton.internal.openssl.ERR_get_error
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.toKString
import kotlinx.cinterop.usePinned

/**
 * This exception is mostly the cause of another [KryptonException] or subtypes like [InitializationException] and contains all errors
 * extracted from OpenSSL.
 *
 * @param codes    The OpenSSL error codes
 * @param messages The messages out of the error codes
 *
 * @author Cedric Hammes
 * @since  29/09/2024
 */
@Suppress("MemberVisibilityCanBePrivate") // We want these members public so developers can access them
class OpenSSLException private constructor(
    val codes: List<Long>,
    val messages: List<String>
) : KryptonException(messages.joinToString("\n")) {

    companion object {
        /**
         * @author Cedric Hammes
         * @since  29/09/2024
         */
        fun create(): OpenSSLException {
            val errorCodes = mutableListOf<Long>()
            val messages = mutableListOf<String>()
            var error = ERR_get_error()
            while (error.toLong() != 0L) {
                errorCodes.add(error.toLong())
                val errorBuffer = ByteArray(0)
                errorBuffer.usePinned { bufferPointer ->
                    ERR_error_string(error, bufferPointer.addressOf(0))
                }
                messages.add(errorBuffer.toKString())
                error = ERR_get_error()
            }
            return OpenSSLException(errorCodes, messages)
        }
    }
}
