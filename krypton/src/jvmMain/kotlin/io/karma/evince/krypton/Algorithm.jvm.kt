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
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import io.karma.evince.krypton.impl.DefaultJavaCipher
import io.karma.evince.krypton.impl.DefaultJavaSignature
import io.karma.evince.krypton.parameters.CBCCipherParameters
import io.karma.evince.krypton.parameters.CipherParameters
import io.karma.evince.krypton.parameters.DHKeypairGeneratorParameters
import io.karma.evince.krypton.parameters.ECKeypairGeneratorParameters
import io.karma.evince.krypton.parameters.GCMCipherParameters
import io.karma.evince.krypton.parameters.KeyGeneratorParameters
import io.karma.evince.krypton.parameters.KeypairGeneratorParameters
import io.karma.evince.krypton.parameters.ParameterGeneratorParameters
import io.karma.evince.krypton.parameters.Parameters
import io.karma.evince.krypton.parameters.SignatureParameters
import io.karma.evince.krypton.utils.JavaCryptoHelper
import java.security.AlgorithmParameterGenerator
import java.security.KeyPair
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import javax.crypto.spec.DHParameterSpec
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

private typealias JavaKeyGenerator = javax.crypto.KeyGenerator
private typealias JavaKeyPairGenerator = java.security.KeyPairGenerator
private typealias JavaKeyAgreement = javax.crypto.KeyAgreement

internal fun java.math.BigInteger.toBigInteger(): BigInteger =
    BigInteger.fromByteArray(
        toByteArray(), when (signum()) {
            1 -> Sign.POSITIVE
            -1 -> Sign.NEGATIVE
            else -> Sign.ZERO
        }
    )

internal fun KeyPair.toKryptonKeypair(algorithm: Algorithm, usages: Array<Key.Usage>): Keypair = Keypair(
    Key(private, algorithm, usages.forType(Key.Type.PRIVATE)),
    Key(public, algorithm, usages.forType(Key.Type.PUBLIC))
)

internal actual class DefaultHashProvider actual constructor(algorithm: Algorithm) : Hash {
    private val messageDigest: MessageDigest = MessageDigest.getInstance(algorithm.literal)
    override fun hash(input: ByteArray): ByteArray = messageDigest.digest(input)
}

internal actual class DefaultSymmetricCipher actual constructor(private val algorithm: Algorithm) : KeyGenerator, CipherFactory {
    private val keyGenerator: JavaKeyGenerator by lazy { JavaKeyGenerator.getInstance(algorithm.literal) }
    override fun createCipher(parameters: CipherParameters): Cipher = DefaultJavaCipher(parameters) { _ ->
        when (parameters.blockMode ?: algorithm.defaultBlockMode) {
            Algorithm.BlockMode.CBC -> IvParameterSpec((parameters as CBCCipherParameters).iv)
            Algorithm.BlockMode.GCM -> (parameters as GCMCipherParameters).let { GCMParameterSpec(it.tagLength, it.iv) }
            else -> null
        }
    }

    override fun generateKey(parameters: KeyGeneratorParameters): Key {
        keyGenerator.init(parameters.bitSize.toInt())
        return Key(keyGenerator.generateKey(), algorithm, parameters.usages)
    }
}

internal actual class DefaultAsymmetricCipher actual constructor(private val algorithm: Algorithm) : KeypairGenerator, SignatureFactory,
    CipherFactory {
    private val keypairGenerator: JavaKeyPairGenerator = JavaKeyPairGenerator.getInstance(algorithm.literal)

    override fun generateKeypair(parameters: KeypairGeneratorParameters): Keypair {
        keypairGenerator.initialize(parameters.bitSize.toInt())
        return keypairGenerator.generateKeyPair().toKryptonKeypair(algorithm, parameters.usages)
    }

    override fun createSignature(parameters: SignatureParameters): Signature = DefaultJavaSignature(parameters)
    override fun createCipher(parameters: CipherParameters): Cipher = DefaultJavaCipher(parameters) { _ -> null }
}

internal actual class DefaultKeyAgreement actual constructor(
    private val algorithm: Algorithm
) : KeypairGenerator, ParameterGenerator, KeyAgreement {
    private val parameterGenerator: AlgorithmParameterGenerator by lazy { AlgorithmParameterGenerator.getInstance(algorithm.literal) }
    private val keyAgreement: JavaKeyAgreement = JavaKeyAgreement.getInstance(algorithm.literal)
    private val keypairGenerator: JavaKeyPairGenerator = JavaKeyPairGenerator.getInstance(algorithm.literal)

    override fun generateKeypair(parameters: KeypairGeneratorParameters): Keypair {
        keypairGenerator.initialize(when (algorithm) {
            DefaultAlgorithm.ECDH -> ECGenParameterSpec((parameters as ECKeypairGeneratorParameters).curve.toString())
            DefaultAlgorithm.DH -> (parameters as DHKeypairGeneratorParameters).let {
                DHParameterSpec(
                    it.p.toJavaBigInteger(),
                    it.g.toJavaBigInteger(),
                    parameters.bitSize.toInt()
                )
            }

            else -> throw IllegalArgumentException()
        })
        return keypairGenerator.generateKeyPair().toKryptonKeypair(algorithm, parameters.usages)
    }

    // It would be very nice to be able to concatenate two crypto providers together but idk how to implement that into the cryptography
    // provider API :/
    @Suppress("UNCHECKED_CAST")
    override fun <T : Parameters> generateParameters(parameters: ParameterGeneratorParameters): T = when (algorithm) {
        DefaultAlgorithm.DH -> {
            parameterGenerator.init(parameters.bits.toInt())
            parameterGenerator.generateParameters().getParameterSpec(DHParameterSpec::class.java).let { spec ->
                DHKeypairGeneratorParameters(spec.p.toBigInteger(), spec.g.toBigInteger(), parameters.bits, arrayOf(Key.Usage.DERIVE))
            }
        }

        else -> throw InitializationException("Parameter generation function is not available for algorithm '${algorithm.literal}'")
    } as? T ?: throw GeneratorException("Invalid type conversion to specified parameter type")

    override fun computeSecret(privateKey: Key, peerPublicKey: Key): ByteArray {
        keyAgreement.init(privateKey.javaKey)
        keyAgreement.doPhase(peerPublicKey.javaKey, true)
        return keyAgreement.generateSecret()
    }
}

internal actual fun installRequiredProviders() {
    JavaCryptoHelper.installBouncyCastleProviders()
}
