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

import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import libssl.BIGNUM
import libssl.BN_bin2bn

/** @suppress **/
internal fun BigInteger.toBigNumber(cache: MutableList<CPointer<BIGNUM>>? = null): CPointer<BIGNUM> {
    val number = requireNotNull(this.toByteArray().let { bytes ->
        bytes.usePinned { pinnedBytes -> BN_bin2bn(pinnedBytes.addressOf(0).reinterpret(), bytes.size, null) }
    })
    cache?.add(number)
    return number
}
