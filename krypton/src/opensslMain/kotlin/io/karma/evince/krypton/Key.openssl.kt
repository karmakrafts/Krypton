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

import io.karma.evince.krypton.internal.openssl.BIO
import io.karma.evince.krypton.internal.openssl.BIO_ctrl_pending
import io.karma.evince.krypton.internal.openssl.BIO_free
import io.karma.evince.krypton.internal.openssl.EVP_PKEY
import io.karma.evince.krypton.internal.openssl.EVP_PKEY_free
import io.karma.evince.krypton.internal.openssl.EVP_PKEY_get_bits
import kotlinx.cinterop.CPointer

fun Keypair.Companion.from(private: AsymmetricKey, public: AsymmetricKey): Keypair = Keypair(private.key, public.key)
value class AsymmetricKey(internal val key: Key) {
    constructor(type: Key.Type, algorithm: Algorithm, usages: Array<Key.Usage>, data: CPointer<EVP_PKEY>)
        : this(Key(type, algorithm, usages, Key.KeyBody.EVPKeyBody(data)))
    fun internalKey(): CPointer<EVP_PKEY> = (key.body as Key.KeyBody.EVPKeyBody).key
}

value class SymmetricKey(internal val key: Key) {
    constructor(type: Key.Type, algorithm: Algorithm, usages: Array<Key.Usage>, data: CPointer<BIO>)
            : this(Key(type, algorithm, usages, Key.KeyBody.DataKeyBody(data)))
    fun internalKey(): CPointer<BIO> = (key.body as Key.KeyBody.DataKeyBody).data
}

@Suppress("MemberVisibilityCanBePrivate")
actual class Key internal constructor(
    actual val type: Type,
    actual val algorithm: Algorithm,
    actual val usages: Array<Usage>,
    val body: KeyBody
) : AutoCloseable {
    internal fun size() = body.size()

    actual override fun close() {
        body.close()
    }

    sealed interface KeyBody : AutoCloseable {
        fun size(): Int

        class DataKeyBody internal constructor(internal val data: CPointer<BIO>) : KeyBody {
            override fun size(): Int = BIO_ctrl_pending(data).toInt()

            override fun close() {
                BIO_free(data)
            }
        }

        class EVPKeyBody internal constructor(internal val key: CPointer<EVP_PKEY>) : KeyBody {
            override fun size(): Int = EVP_PKEY_get_bits(key)

            override fun close() {
                EVP_PKEY_free(key)
            }
        }
    }


    actual enum class Usage(actual val supportedTypes: Array<Type>) {
        ENCRYPT(Type.entries.toTypedArray()),
        DECRYPT(Type.entries.toTypedArray()),
        DERIVE(arrayOf(Type.PUBLIC, Type.PRIVATE)),
        SIGN(arrayOf(Type.PUBLIC, Type.PRIVATE)),
        VERIFY(arrayOf(Type.PUBLIC, Type.PRIVATE))
    }

    actual enum class Type {
        PUBLIC, PRIVATE, OTHER
    }
}
