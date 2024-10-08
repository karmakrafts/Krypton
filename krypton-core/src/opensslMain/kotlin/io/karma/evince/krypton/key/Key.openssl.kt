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
actual class Key(actual val type: KeyType, actual val algorithm: String, internal val body: KeyBody) : AutoCloseable {
    constructor(type: KeyType, algorithm: String, data: CPointer<BIO>) :
            this(type, algorithm, KeyBody.DataKeyBody(data))
    
    constructor(type: KeyType, algorithm: String, data: CPointer<EVP_PKEY>) :
            this(type, algorithm, KeyBody.EVPKeyBody(data))
    
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
}
