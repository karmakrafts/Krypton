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

import com.ionspin.kotlin.bignum.integer.BigInteger
import io.karma.evince.krypton.Algorithm
import io.karma.evince.krypton.annotations.UncheckedKryptonAPI
import io.karma.evince.krypton.ec.EllipticCurve

expect class KeyPairGenerator @UncheckedKryptonAPI constructor(
    algorithm: String,
    parameter: KeyPairGeneratorParameter
) : AutoCloseable {
    constructor(algorithm: Algorithm, parameter: KeyPairGeneratorParameter)

    fun generate(): KeyPair
    override fun close()
}

open class KeyPairGeneratorParameter(internal val size: Int)

class ECKeyPairGeneratorParameter(internal val curve: EllipticCurve) : KeyPairGeneratorParameter(0)
class DHKeyPairGeneratorParameter(internal val p: BigInteger, internal val g: BigInteger, bits: Int) :
    KeyPairGeneratorParameter(bits)