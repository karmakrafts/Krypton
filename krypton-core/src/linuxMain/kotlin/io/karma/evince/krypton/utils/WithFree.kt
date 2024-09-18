package io.karma.evince.krypton.utils

import kotlinx.cinterop.CPointed
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.NativePtr

/**
 * See in https://gitlab.com/connect2x/qca/-/blob/main/qca-crypto/src/opensslMain/kotlin/de/connect2x/qca/crypto/withFree.kt?ref_type=heads
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

inline fun <T> withFree(block: WithFree.() -> T): T {
    val withFree = WithFree()
    return try {
        withFree.block()
    } finally {
        withFree.freeAll()
    }
}

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
