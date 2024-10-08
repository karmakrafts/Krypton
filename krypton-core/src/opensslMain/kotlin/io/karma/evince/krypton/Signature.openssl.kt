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

import io.karma.evince.krypton.internal.openssl.*
import io.karma.evince.krypton.key.Key
import io.karma.evince.krypton.utils.ErrorHelper
import io.karma.evince.krypton.utils.checkNotNull
import io.karma.evince.krypton.utils.withFree
import kotlinx.cinterop.*

/**
 *
 * @author Cedric Hammes
 * @since  27/09/2024
 */
actual class Signature actual constructor(
    private val key: Key,
    algorithm: String,
    private val parameters: SignatureParameters
) {
    actual constructor(key: Key, algorithm: Algorithm, parameters: SignatureParameters) :
            this(key, algorithm.checkScopeOrError(Algorithm.Scope.SIGNATURE).toString(), parameters)
    
    init {
        if (parameters.type.keyType != key.type) {
            throw InitializationException("Invalid key type '${key.type}', expected ${parameters.type.keyType}")
        }
    }
    
    actual fun sign(data: ByteArray): ByteArray = withFree {
        val context = EVP_MD_CTX_new().checkNotNull().freeAfter(::EVP_MD_CTX_free)
        val digest = EVP_get_digestbyname(parameters.digest).checkNotNull().freeAfter(::EVP_MD_free)
        if (EVP_DigestSignInit(context, null, digest, null, (key.body as Key.KeyBody.EVPKeyBody).key) != 1) {
            throw InitializationException(
                message = "Unable to initialize digest for signature",
                cause = ErrorHelper.createOpenSSLException()
            )
        }
        
        data.usePinned { input ->
            memScoped {
                val outputSize = alloc<ULong>(0U)
                if (EVP_DigestSign(
                        ctx = context,
                        sigret = null,
                        siglen = outputSize.ptr,
                        tbs = input.addressOf(0).reinterpret(),
                        tbslen = data.size.toULong()
                    ) != 1
                ) {
                    throw KryptonException("Unable to get signature length", ErrorHelper.createOpenSSLException())
                }
                
                val output = ByteArray(outputSize.value.toInt())
                output.usePinned { pinned ->
                    if (EVP_DigestSign(
                            ctx = context,
                            sigret = pinned.addressOf(0).reinterpret(),
                            siglen = outputSize.ptr,
                            tbs = input.addressOf(0).reinterpret(),
                            tbslen = data.size.toULong()
                        ) != 1
                    ) {
                        throw KryptonException("Unable to sign data", ErrorHelper.createOpenSSLException())
                    }
                }
                output
            }
        }
    }
    
    actual fun verify(signature: ByteArray, data: ByteArray): Boolean = withFree {
        val context = EVP_MD_CTX_new().checkNotNull().freeAfter(::EVP_MD_CTX_free)
        val digest = EVP_get_digestbyname(parameters.digest).checkNotNull().freeAfter(::EVP_MD_free)
        if (EVP_DigestVerifyInit(context, null, digest, null, (key.body as Key.KeyBody.EVPKeyBody).key) != 1) {
            throw InitializationException(
                message = "Unable to initialize digest for signature",
                cause = ErrorHelper.createOpenSSLException()
            )
        }
        
        data.usePinned { pinnedInput ->
            signature.usePinned { pinnedSignature ->
                when (EVP_DigestVerify(
                    ctx = context,
                    sigret = pinnedSignature.addressOf(0).reinterpret(),
                    siglen = signature.size.toULong(),
                    tbs = pinnedInput.addressOf(0).reinterpret(),
                    tbslen = data.size.toULong()
                )) {
                    1 -> true
                    0 -> false
                    else -> throw KryptonException("Unable to validate signature", ErrorHelper.createOpenSSLException())
                }
            }
        }
    }
}
