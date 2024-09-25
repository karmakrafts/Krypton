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

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import io.karma.evince.krypton.internal.openssl.*
import kotlinx.cinterop.*

/** @suppress **/
internal fun <T> T?.checkNotNull(message: String? = "The allocation of a object is failed"): T =
    this ?: throw RuntimeException(message, ErrorHelper.createOpenSSLException())

internal fun <T : Any, R> T?.pinnedNotNull(closure: (Pinned<T>) -> R?): R? = this?.usePinned(closure)

/** @suppress **/
internal fun BigInteger.toOpenSSLBigNumber(store: MutableList<CPointer<BIGNUM>>? = null): CPointer<BIGNUM> =
    this.toByteArray().let { it.usePinned { pinned -> BN_bin2bn(pinned.addressOf(0).reinterpret(), it.size, null) } }
        .checkNotNull().also {
            store?.add(it)
        }

internal fun CPointer<BIGNUM>.toBigInteger(): BigInteger {
    val data = ByteArray((BN_num_bits(this) + 7) / 8)
    data.usePinned {
        if (BN_bn2bin(this, it.addressOf(0).reinterpret()) < 1)
            throw RuntimeException(
                "Unable to convert OpenSSL big number to BigInteger",
                ErrorHelper.createOpenSSLException()
            )
    }
    return BigInteger.fromByteArray(data, Sign.POSITIVE)
}