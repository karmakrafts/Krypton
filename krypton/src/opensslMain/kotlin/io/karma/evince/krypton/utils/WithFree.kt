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

import kotlinx.cinterop.CPointed
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.NativePtr

/**
 * See in https://gitlab.com/connect2x/qca/-/blob/main/qca-crypto/src/opensslMain/kotlin/de/connect2x/qca/crypto/withFree.kt?ref_type=heads
 * @suppress
 */
class WithFree {
    private val freeOperations = mutableListOf<() -> Unit>()
    private val exceptionFreeOperations = mutableListOf<() -> Unit>()

    fun <T : CPointed> CPointerVar<T>.freeAfterOnException(free: (NativePtr) -> Unit): CPointerVar<T> =
        also {
            exceptionFreeOperations.add {
                free(it.rawPtr)
            }
        }

    fun <T : CPointed> CPointerVar<T>.freeAfter(free: (NativePtr) -> Unit): CPointerVar<T> =
        also {
            freeOperations.add {
                free(it.rawPtr)
            }
        }

    fun <T : CPointed> CPointer<T>.freeAfter(free: (CPointer<T>) -> Unit): CPointer<T> =
        also {
            freeOperations.add {
                free(it)
            }
        }

    fun <T : CPointed> CPointer<T>.freeAfterOnException(free: (CPointer<T>) -> Unit): CPointer<T> =
        also {
            exceptionFreeOperations.add {
                free(it)
            }
        }

    @PublishedApi
    internal fun freeAll() {
        freeOperations.reversed().forEach { it() }
        freeOperations.clear()
    }

    @PublishedApi
    internal fun freeAllOnException() {
        exceptionFreeOperations.reversed().forEach { it() }
        exceptionFreeOperations.clear()
    }
}

/** @suppress **/
inline fun <T> withFree(block: WithFree.() -> T): T {
    val withFree = WithFree()
    return try {
        withFree.block()
    } finally {
        withFree.freeAll()
    }
}

/** @suppress **/
inline fun <T> withFreeWithException(closure: WithFree.() -> T): T {
    val withFree = WithFree()
    return try {
        withFree.closure()
    } catch (ex: Exception) {
        withFree.freeAllOnException()
        throw ex
    } finally {
        withFree.freeAll()
    }
}
