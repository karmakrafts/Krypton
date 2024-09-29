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
import com.ionspin.kotlin.bignum.integer.Sign
import io.karma.evince.krypton.impl.DefaultOpenSSLCipher
import io.karma.evince.krypton.impl.DefaultOpenSSLSignature
import io.karma.evince.krypton.impl.internalGenerateECKeypair
import io.karma.evince.krypton.impl.internalGenerateKeypair
import io.karma.evince.krypton.impl.internalGenerateKeypairWithNid
import io.karma.evince.krypton.impl.nidParameterGenerator
import io.karma.evince.krypton.internal.openssl.*
import io.karma.evince.krypton.parameters.CipherParameters
import io.karma.evince.krypton.parameters.DHKeypairGeneratorParameters
import io.karma.evince.krypton.parameters.KeyGeneratorParameters
import io.karma.evince.krypton.parameters.KeypairGeneratorParameters
import io.karma.evince.krypton.parameters.ParameterGeneratorParameters
import io.karma.evince.krypton.parameters.Parameters
import io.karma.evince.krypton.parameters.SignatureParameters
import io.karma.evince.krypton.utils.checkNotNull
import io.karma.evince.krypton.utils.withFree
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ULongVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value

internal fun CPointer<BIGNUM>.toBigInteger(): BigInteger {
    val data = ByteArray((BN_num_bits(this) + 7) / 8)
    data.usePinned {
        if (BN_bn2bin(this, it.addressOf(0).reinterpret()) < 1)
            throw RuntimeException("Unable to convert OpenSSL big number to BigInteger", OpenSSLException.create())
    }
    return BigInteger.fromByteArray(data, Sign.POSITIVE)
}

/** @suppress **/
internal fun BigInteger.toOpenSSLBigNumber(): CPointer<BIGNUM> =
    this.toByteArray().let { it.usePinned { pinned -> BN_bin2bn(pinned.addressOf(0).reinterpret(), it.size, null) } }.checkNotNull()

internal fun Algorithm.getMessageDigest(): CPointer<EVP_MD> = when (this) {
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
    override fun hash(input: ByteArray): ByteArray = withFree {
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
    override fun generateKey(parameters: KeyGeneratorParameters): Key = SymmetricKey(
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

    override fun createCipher(parameters: CipherParameters): Cipher = DefaultOpenSSLCipher(parameters)
}

internal actual class DefaultAsymmetricCipher actual constructor(private val algorithm: Algorithm) : KeypairGenerator, SignatureFactory,
    CipherFactory {
    override fun generateKeypair(parameters: KeypairGeneratorParameters): Keypair = when (algorithm) {
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

    override fun createSignature(parameters: SignatureParameters): Signature = DefaultOpenSSLSignature(parameters)
    override fun createCipher(parameters: CipherParameters): Cipher = DefaultOpenSSLCipher(parameters)
}

internal actual class DefaultKeyAgreement actual constructor(
    private val algorithm: Algorithm
) : KeypairGenerator, ParameterGenerator, KeyAgreement {
    override fun generateKeypair(parameters: KeypairGeneratorParameters): Keypair = when (algorithm) {
        DefaultAlgorithm.DH -> internalGenerateKeypair(
            algorithm = algorithm,
            parameters = parameters,
            contextGenerator = {
                val params = parameters as DHKeypairGeneratorParameters
                val dh = DH_new().checkNotNull().freeAfter(::DH_free)
                val prime = params.p.toOpenSSLBigNumber().checkNotNull()
                val generator = params.g.toOpenSSLBigNumber().checkNotNull()
                if (DH_set0_pqg(dh, prime, null, generator) != 1) {
                    throw RuntimeException(
                        message = "Unable to initialize prime and generator parameter",
                        cause = OpenSSLException.create()
                    )
                }

                val keyGeneratorParameters = EVP_PKEY_new().checkNotNull()
                if (EVP_PKEY_set1_DH(keyGeneratorParameters, dh) != 1) {
                    throw RuntimeException(
                        message = "Unable to apply DH parameters to keypair generator",
                        cause = OpenSSLException.create()
                    )
                }

                EVP_PKEY_CTX_new(keyGeneratorParameters, null)
            },
            contextConfigurator = { _, _: DHKeypairGeneratorParameters -> }
        )
        DefaultAlgorithm.ECDH -> internalGenerateECKeypair(algorithm, parameters)

        else -> throw IllegalArgumentException("Unsupported algorithm '${algorithm.literal}'")
    }

    // It would be very nice to be able to concatenate two crypto providers together but idk how to implement that into the cryptography
    // provider API :/
    @Suppress("UNCHECKED_CAST")
    override fun <T : Parameters> generateParameters(parameters: ParameterGeneratorParameters): T = when (algorithm) {
        DefaultAlgorithm.DH -> nidParameterGenerator(
            nid = EVP_PKEY_DH,
            configurator = { generator ->
                if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(generator, parameters.bits.toInt()) != 1)
                    throw RuntimeException("Unable to set prime length")
            },
            outputFactory = { rawParameters ->
                val dhParameters = EVP_PKEY_get1_DH(rawParameters).checkNotNull().freeAfter(::DH_free)
                DHKeypairGeneratorParameters(
                    DH_get0_p(dhParameters).checkNotNull().toBigInteger(),
                    DH_get0_g(dhParameters).checkNotNull().toBigInteger(),
                    parameters.bits,
                    arrayOf(Key.Usage.DERIVE)
                )
            }
        )

        else -> throw InitializationException("Parameter generation function is not available for algorithm '${algorithm.literal}'")
    } as? T ?: throw GeneratorException("Invalid type conversion to specified parameter type")

    override fun computeSecret(privateKey: Key, peerPublicKey: Key): ByteArray = withFree {
        val context = EVP_PKEY_CTX_new(AsymmetricKey(privateKey).internalKey(), null).checkNotNull().freeAfter(::EVP_PKEY_CTX_free)
        if (EVP_PKEY_derive_init(context) != 1) {
            throw InitializationException("Unable to initialize secret computation", OpenSSLException.create())
        }
        if (EVP_PKEY_derive_set_peer(context, AsymmetricKey(peerPublicKey).internalKey()) != 1) {
            throw InitializationException("Unable to st peer's public key", OpenSSLException.create())
        }

        memScoped {
            val secretLength = alloc<ULongVar>()
            if (EVP_PKEY_derive(context, null, secretLength.ptr) != 1) {
                throw GeneratorException("Unable to acquire length of secret", OpenSSLException.create())
            }
            val secret = UByteArray(secretLength.value.toInt())
            secret.usePinned { pinnedSecret ->
                if (EVP_PKEY_derive(context, pinnedSecret.addressOf(0), secretLength.ptr) != 1) {
                    throw GeneratorException("Unable to acquire length of secret", OpenSSLException.create())
                }
            }
            secret.toByteArray()
        }
    }
}

internal actual fun installRequiredProviders() {}
