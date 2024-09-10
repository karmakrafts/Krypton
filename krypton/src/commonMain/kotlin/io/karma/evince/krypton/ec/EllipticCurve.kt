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

package io.karma.evince.krypton.ec

import com.ionspin.kotlin.bignum.integer.BigInteger

/**
 * This interface is the template for the implementation of elliptic curves into the Krypton API. It allows the user to
 * create custom curves or use one of the by-default provided curves.
 *
 * @author Cedric Hammes
 * @since  10/09/2024
 */
interface EllipticCurve : AutoCloseable

/**
 * This enum represents all by-default provided elliptic curves. All of these curves are implemented on all platforms
 * supported by Krypton itself. It is recommended to prefer these curves over custom curves.
 *
 * @author Cedric Hammes
 * @since  10/09/024
 */
enum class DefaultEllipticCurve(private val literal: String, val bits: Int) : EllipticCurve {
    PRIME192V1("prime192v1", 192),
    PRIME192V2("prime192v2", 192),
    PRIME192V3("prime192v3", 192),
    PRIME239V1("prime239v1", 239),
    PRIME239V2("prime239v2", 239),
    PRIME239V3("prime239v3", 239),
    PRIME256V1("prime256v1", 256),
    BRAINPOOL_P160T1("brainpoolP160t1", 160),
    BRAINPOOL_P192T1("brainpoolP192t1", 192),
    BRAINPOOL_P224T1("brainpoolP224t1", 224),
    BRAINPOOL_P256T1("brainpoolP256t1", 256),
    BRAINPOOL_P320T1("brainpoolP320t1", 320),
    BRAINPOOL_P384T1("brainpoolP384t1", 384),
    BRAINPOOL_P512T1("brainpoolP512t1", 512),
    BRAINPOOL_P160R1("brainpoolP160r1", 160),
    BRAINPOOL_P192R1("brainpoolP192r1", 192),
    BRAINPOOL_P224R1("brainpoolP224r1", 224),
    BRAINPOOL_P320R1("brainpoolP320r1", 320),
    BRAINPOOL_P256R1("brainpoolP256r1", 256),
    BRAINPOOL_P384R1("brainpoolP384r1", 384),
    BRAINPOOL_P512R1("brainpoolP512r1", 512);

    override fun close() {}
    override fun toString(): String = literal
}

class EllipticCurveParameters {
    lateinit var name: String
    lateinit var generatorPoint: Pair<BigInteger, BigInteger>
    lateinit var field: Field
    lateinit var a: BigInteger
    lateinit var b: BigInteger
    lateinit var order: BigInteger

    sealed interface Field {
        data class Fp(internal val p: BigInteger): Field
    }
}

expect class ParameterizedEllipticCurve(parameters: EllipticCurveParameters) : EllipticCurve

fun curve(closure: EllipticCurveParameters.() -> Unit): ParameterizedEllipticCurve =
    ParameterizedEllipticCurve(EllipticCurveParameters().apply(closure))