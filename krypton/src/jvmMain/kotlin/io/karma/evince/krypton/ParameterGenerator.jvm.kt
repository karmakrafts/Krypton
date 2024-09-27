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
import io.karma.evince.krypton.key.DHKeyPairGeneratorParameters
import io.karma.evince.krypton.key.KeyPairGeneratorParameters
import java.security.AlgorithmParameterGenerator
import javax.crypto.spec.DHParameterSpec

internal fun java.math.BigInteger.toBigInteger(): BigInteger =
    BigInteger.fromByteArray(toByteArray(), when(signum()) {
        1 -> Sign.POSITIVE
        -1 -> Sign.NEGATIVE
        else -> Sign.ZERO
    })

/**
 * @author Cedric Hammes
 * @since  18/09/2024
 * @suppress
 */
actual class ParameterGenerator actual constructor(
    private val algorithm: String,
    private val parameters: ParameterGeneratorParameters
) {
    private val generator: AlgorithmParameterGenerator = AlgorithmParameterGenerator.getInstance(algorithm)
    
    actual constructor(algorithm: Algorithm, parameters: ParameterGeneratorParameters) :
            this(algorithm.checkScopeOrError(Algorithm.Scope.PARAMETER_GENERATOR).toString(), parameters)
    
    init {
        generator.init(parameters.bits)
    }
    
    actual fun generate(): KeyPairGeneratorParameters = generator.generateParameters().let { params ->
        when(algorithm) {
            "DH" -> params.getParameterSpec(DHParameterSpec::class.java).let { spec ->
                DHKeyPairGeneratorParameters(spec.p.toBigInteger(), spec.g.toBigInteger(), parameters.bits)
            }
            else -> throw IllegalArgumentException("Unsupported algorithm '$algorithm'")
        }
    }
}
