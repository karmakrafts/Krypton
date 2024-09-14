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

import io.karma.evince.krypton.Algorithm
import io.karma.evince.krypton.ec.DefaultEllipticCurve
import io.karma.evince.krypton.ec.ParameterizedEllipticCurve
import io.karma.evince.krypton.utils.JavaCryptoHelper
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

/** @suppress **/
internal typealias JavaKeyPairGenerator = java.security.KeyPairGenerator

actual class KeyPairGenerator actual constructor(
    algorithm: String, parameter: KeyPairGeneratorParameter
) : AutoCloseable {
    private val keyPairGenerator: JavaKeyPairGenerator

    actual constructor(
        algorithm: Algorithm, parameter: KeyPairGeneratorParameter
    ) : this(algorithm.toString(), parameter)

    init {
        JavaCryptoHelper.installBouncyCastleProviders()
        if (!JavaCryptoHelper.getAlgorithms<JavaKeyPairGenerator>().contains(algorithm)) throw IllegalArgumentException(
            "The algorithm '$algorithm' is not available, the following are officially supported by Krypton: ${
                Algorithm.entries.filter { it.asymmetric }.joinToString(", ")
            }"
        )

        Security.addProvider(BouncyCastleProvider())
        keyPairGenerator = JavaKeyPairGenerator.getInstance(algorithm)
        println("DingDingDing")
        when (parameter) {
            is ECKeyPairGeneratorParameter -> keyPairGenerator.initialize(
                when (val ellipticCurve = parameter.ellipticCurve) {
                    is DefaultEllipticCurve -> ECNamedCurveTable.getParameterSpec(ellipticCurve.toString())
                    is ParameterizedEllipticCurve -> ellipticCurve.parameterSpec
                    else -> throw IllegalArgumentException("Unsupported elliptic curve class type '${ellipticCurve}'")
                }
            )

            else -> keyPairGenerator.initialize(parameter.size)
        }
    }

    actual fun generate(): KeyPair = keyPairGenerator.generateKeyPair()
        .let { KeyPair(Key(KeyType.PUBLIC, it.public), Key(KeyType.PRIVATE, it.private)) }

    actual override fun close() {}
}
