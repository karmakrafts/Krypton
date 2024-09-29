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

import io.karma.evince.krypton.impl.DefaultJavaCipher
import io.karma.evince.krypton.impl.DefaultJavaSignature
import io.karma.evince.krypton.parameters.CBCCipherParameters
import io.karma.evince.krypton.parameters.CipherParameters
import io.karma.evince.krypton.parameters.GCMCipherParameters
import io.karma.evince.krypton.parameters.KeyGeneratorParameters
import io.karma.evince.krypton.parameters.KeypairGeneratorParameters
import io.karma.evince.krypton.parameters.SignatureParameters
import java.security.MessageDigest
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

private typealias JavaKeyGenerator = javax.crypto.KeyGenerator
private typealias JavaKeyPairGenerator = java.security.KeyPairGenerator

internal actual class DefaultHashProvider actual constructor(algorithm: Algorithm) : Hash {
    private val messageDigest: MessageDigest = MessageDigest.getInstance(algorithm.literal)
    override suspend fun hash(input: ByteArray): ByteArray = messageDigest.digest(input)
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

    override suspend fun generateKey(parameters: KeyGeneratorParameters): Key {
        keyGenerator.init(parameters.bitSize.toInt())
        return Key(keyGenerator.generateKey(), algorithm, parameters.usages)
    }
}

internal actual class DefaultAsymmetricCipher actual constructor(private val algorithm: Algorithm) : KeypairGenerator, SignatureFactory,
    CipherFactory {
    private val keypairGenerator: JavaKeyPairGenerator = JavaKeyPairGenerator.getInstance(algorithm.literal)

    override suspend fun generateKeypair(parameters: KeypairGeneratorParameters): Keypair {
        keypairGenerator.initialize(parameters.bitSize.toInt())
        val keypair = keypairGenerator.generateKeyPair()
        return Keypair(Key(keypair.private, algorithm, parameters.usages), Key(keypair.public, algorithm, parameters.usages))
    }

    override fun createSignature(parameters: SignatureParameters): Signature = DefaultJavaSignature(parameters)
    override fun createCipher(parameters: CipherParameters): Cipher = DefaultJavaCipher(parameters) { _ -> null }
}
