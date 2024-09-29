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

import io.karma.evince.krypton.impl.DefaultOpenSSLCipher
import io.karma.evince.krypton.impl.internalGenerateKeypairWithNid
import io.karma.evince.krypton.internal.openssl.*
import io.karma.evince.krypton.parameters.CipherParameters
import io.karma.evince.krypton.parameters.KeyGeneratorParameters
import io.karma.evince.krypton.parameters.KeypairGeneratorParameters
import io.karma.evince.krypton.utils.checkNotNull
import io.karma.evince.krypton.utils.withFree
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned

internal fun Algorithm.getMessageDigest(): CPointer<EVP_MD> = when(this) {
    DefaultAlgorithm.MD5 -> EVP_md5()
    DefaultAlgorithm.SHA1 -> EVP_sha1()
    DefaultAlgorithm.SHA224 -> EVP_sha224()
    DefaultAlgorithm.SHA256 -> EVP_sha256()
    DefaultAlgorithm.SHA384 -> EVP_sha384()
    DefaultAlgorithm.SHA512 -> EVP_sha512()
    DefaultAlgorithm.SHA3_224 -> EVP_sha3_224()
    DefaultAlgorithm.SHA3_256 -> EVP_sha3_256()
    DefaultAlgorithm.SHA3_384 -> EVP_sha3_384()
    DefaultAlgorithm.SHA3_512 -> EVP_sha3_512()
    else -> throw IllegalArgumentException("'${this.literal}' is not a message digest")
}.checkNotNull()

internal actual class DefaultHashProvider actual constructor(private val algorithm: Algorithm) : Hash {
    override suspend fun hash(input: ByteArray): ByteArray = withFree {
        val digest = algorithm.getMessageDigest().freeAfter(::EVP_MD_free)
        val digestContext = EVP_MD_CTX_new().checkNotNull().freeAfter(::EVP_MD_CTX_free)
        if (EVP_DigestInit_ex(digestContext, digest, null) != 1) {
            throw InitializationException("Unable to initialize message digest for '${algorithm.literal}'", OpenSSLException.create())
        }

        input.usePinned { inputPointer ->
            if (EVP_DigestUpdate(digestContext, inputPointer.addressOf(0), input.size.toULong()) != 1) {
                throw KryptonException("Unable to update digest with input", OpenSSLException.create())
            }
        }
        ByteArray(EVP_MD_get_size(digest)).also {
            it.usePinned { outputPointer ->
                memScoped {
                    val outputSize = alloc(it.size.toUInt())
                    if (EVP_DigestFinal_ex(digestContext, outputPointer.addressOf(0).reinterpret(), outputSize.ptr) != 1) {
                        throw KryptonException("Unable to finalize hashing", OpenSSLException.create())
                    }
                }
            }
        }
    }
}

internal actual class DefaultSymmetricCipher actual constructor(private val algorithm: Algorithm) : KeyGenerator, CipherFactory {
    override suspend fun generateKey(parameters: KeyGeneratorParameters): Key = SymmetricKey(
        type = Key.Type.OTHER,
        algorithm = algorithm,
        usages = parameters.usages,
        data = requireNotNull(BIO_new(BIO_s_secmem())).also { data ->
            val bitSize = parameters.bitSize.toInt()
            ByteArray(bitSize).usePinned { dataPtr ->
                if (RAND_bytes(dataPtr.addressOf(0).reinterpret(), bitSize) != 1) {
                    throw KryptonException("Unable to generate random data for key", OpenSSLException.create())
                }
                BIO_write(data, dataPtr.addressOf(0), bitSize)
            }
        }
    ).key

    override fun createCipher(parameters: CipherParameters): Cipher = DefaultOpenSSLCipher(algorithm, parameters)
}

internal actual class DefaultAsymmetricCipher actual constructor(private val algorithm: Algorithm) : KeypairGenerator, CipherFactory {
    override suspend fun generateKeypair(parameters: KeypairGeneratorParameters): Keypair = when(algorithm) {
        DefaultAlgorithm.RSA -> internalGenerateKeypairWithNid<KeypairGeneratorParameters>(
            nid = EVP_PKEY_RSA,
            algorithm = algorithm,
            parameters = parameters,
            contextConfigurator = { context, params ->
                if (EVP_PKEY_CTX_set_rsa_keygen_bits(context, params.bitSize.toInt()) != 1) {
                    throw InitializationException("Unable to set key generation bits for keypair generator", OpenSSLException.create())
                }
            }
        )
        else -> throw IllegalArgumentException("Unsupported algorithm '${algorithm.literal}'")
    }
    override fun createCipher(parameters: CipherParameters): Cipher = DefaultOpenSSLCipher(algorithm, parameters)
}