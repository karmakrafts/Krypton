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

import kotlinx.cinterop.CPointer
import io.karma.evince.krypton.internal.openssl.*

/** @suppress **/
actual class Key(
    actual val type: Type,
    actual val usages: Array<Usage>,
    actual val algorithm: String,
    internal val body: KeyBody
) : AutoCloseable {
    constructor(type: Type, usages: Array<Usage>, algorithm: String, data: CPointer<BIO>) :
            this(type, usages, algorithm, KeyBody.DataKeyBody(data))
    
    constructor(type: Type, usages: Array<Usage>, algorithm: String, data: CPointer<EVP_PKEY>) :
            this(type, usages, algorithm, KeyBody.EVPKeyBody(data))
    
    internal fun size() = body.size()
    
    actual override fun close() {
        body.close()
    }
    
    sealed interface KeyBody : AutoCloseable {
        fun size(): Int
        
        class DataKeyBody(internal val data: CPointer<BIO>) : KeyBody {
            override fun size(): Int = BIO_ctrl_pending(data).toInt()
            
            override fun close() {
                BIO_free(data)
            }
        }
        
        class EVPKeyBody(internal val key: CPointer<EVP_PKEY>) : KeyBody {
            override fun size(): Int = EVP_PKEY_get_bits(key)
            
            override fun close() {
                EVP_PKEY_free(key)
            }
        }
    }

    /**
     * This enum represents all types available for keys. Symmetric if the key is symmetric and public or private if the key
     * is from an asymmetric algorithm.
     *
     * @author Cedric Hammes
     * @since  08/09/2024
     */
    actual enum class Type {
        SYMMETRIC, PUBLIC, PRIVATE
    }

    /**
     * This enum represents all usages for keys available in Krypton. These usages are used by Android and JS to identify the usages of the
     * key what's part of their security architecture so we try to implement this behavior as best as we can on all platforms compatible
     * with Krypton.
     *
     * @author Cedric Hammes
     * @since  28/09/2024
     */
    actual enum class Usage(actual val supportedTypes: Array<Type>) {
        SIGN(arrayOf(Type.PRIVATE)),
        VERIFY(arrayOf(Type.PUBLIC)),
        ENCRYPT(arrayOf(Type.SYMMETRIC, Type.PUBLIC)),
        DECRYPT(arrayOf(Type.SYMMETRIC, Type.PRIVATE)),
        DERIVE(arrayOf(Type.PRIVATE, Type.PUBLIC));
    }
}
