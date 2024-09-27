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

import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import io.karma.evince.krypton.Algorithm
import io.karma.evince.krypton.utils.JavaCryptoHelper
import org.bouncycastle.jce.ECNamedCurveTable
import javax.crypto.spec.DHParameterSpec

/** @suppress **/
internal typealias JavaKeyPairGenerator = java.security.KeyPairGenerator

/** @suppress **/
actual class KeyPairGenerator actual constructor(algorithm: String, parameters: KeyPairGeneratorParameters) {
    private val keyPairGenerator: JavaKeyPairGenerator
    
    actual constructor(
        algorithm: Algorithm, parameters: KeyPairGeneratorParameters
    ) : this(algorithm.validOrError(Algorithm.Scope.KEYPAIR_GENERATOR).toString(), parameters)
    
    init {
        JavaCryptoHelper.installBouncyCastleProviders()
        keyPairGenerator = JavaKeyPairGenerator.getInstance(algorithm)
        when (parameters) {
            is ECKeyPairGeneratorParameters -> keyPairGenerator.initialize(
                ECNamedCurveTable.getParameterSpec(parameters.curve.toString())
            )
            
            is DHKeyPairGeneratorParameters -> keyPairGenerator.initialize(
                DHParameterSpec(parameters.p.toJavaBigInteger(), parameters.g.toJavaBigInteger(), parameters.size)
            )
            
            else -> keyPairGenerator.initialize(parameters.size)
        }
    }
    
    actual fun generate(): KeyPair = keyPairGenerator.generateKeyPair()
        .let { KeyPair(Key(KeyType.PUBLIC, it.public), Key(KeyType.PRIVATE, it.private)) }
}
