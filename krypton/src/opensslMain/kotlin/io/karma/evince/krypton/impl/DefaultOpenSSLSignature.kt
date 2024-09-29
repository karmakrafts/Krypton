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

package io.karma.evince.krypton.impl

import io.karma.evince.krypton.AsymmetricKey
import io.karma.evince.krypton.InitializationException
import io.karma.evince.krypton.KryptonException
import io.karma.evince.krypton.OpenSSLException
import io.karma.evince.krypton.Signature
import io.karma.evince.krypton.internal.openssl.EVP_DigestSign
import io.karma.evince.krypton.internal.openssl.EVP_DigestSignInit
import io.karma.evince.krypton.internal.openssl.EVP_DigestVerify
import io.karma.evince.krypton.internal.openssl.EVP_DigestVerifyInit
import io.karma.evince.krypton.internal.openssl.EVP_MD_CTX_free
import io.karma.evince.krypton.internal.openssl.EVP_MD_CTX_new
import io.karma.evince.krypton.internal.openssl.EVP_MD_free
import io.karma.evince.krypton.internal.openssl.EVP_get_digestbyname
import io.karma.evince.krypton.parameters.SignatureParameters
import io.karma.evince.krypton.utils.checkNotNull
import io.karma.evince.krypton.utils.withFree
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value

class DefaultOpenSSLSignature(private val parameters: SignatureParameters) : Signature {
    override suspend fun sign(input: ByteArray): ByteArray = withFree {
        val digest = EVP_get_digestbyname(parameters.digest.literal).checkNotNull().freeAfter(::EVP_MD_free)
        val context = EVP_MD_CTX_new().checkNotNull().freeAfter(::EVP_MD_CTX_free)
        if (EVP_DigestSignInit(context, null, digest, null, AsymmetricKey(parameters.key).internalKey()) != 1) {
            throw InitializationException("Unable do initialize signature for signing", OpenSSLException.create())
        }

        input.usePinned { pinnedInput ->
            memScoped {
                val outputSize = alloc<ULong>(0U)
                if (EVP_DigestSign(
                    ctx = context,
                    sigret = null,
                    siglen = outputSize.ptr,
                    tbs = pinnedInput.addressOf(0).reinterpret(),
                    tbslen = input.size.toULong()
                ) != 1) {
                    throw KryptonException("Unable to get signature length", OpenSSLException.create())
                }

                ByteArray(outputSize.value.toInt()).also {
                    it.usePinned { pinnedOutput ->
                        if (EVP_DigestSign(
                                ctx = context,
                                sigret = pinnedOutput.addressOf(0).reinterpret(),
                                siglen = outputSize.ptr,
                                tbs = pinnedInput.addressOf(0).reinterpret(),
                                tbslen = input.size.toULong()
                            ) != 1) {
                            throw KryptonException("Unable to get signature length", OpenSSLException.create())
                        }
                    }
                }
            }
        }
    }

    override suspend fun verify(signature: ByteArray, original: ByteArray): Boolean = withFree {
        val digest = EVP_get_digestbyname(parameters.digest.literal).checkNotNull().freeAfter(::EVP_MD_free)
        val context = EVP_MD_CTX_new().checkNotNull().freeAfter(::EVP_MD_CTX_free)
        if (EVP_DigestVerifyInit(context, null, digest, null, AsymmetricKey(parameters.key).internalKey()) != 1) {
            throw InitializationException("Unable do initialize signature for verify", OpenSSLException.create())
        }

        signature.usePinned { pinnedSignature ->
            original.usePinned { pinnedOriginal ->
                when (EVP_DigestVerify(
                    ctx = context,
                    sigret = pinnedSignature.addressOf(0).reinterpret(),
                    siglen = signature.size.toULong(),
                    tbs = pinnedOriginal.addressOf(0).reinterpret(),
                    tbslen = original.size.toULong()
                )) {
                    1 -> true
                    0 -> false
                    else -> throw KryptonException("Unable to validate signature", OpenSSLException.create())
                }

            }
        }
    }
}
