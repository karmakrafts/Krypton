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

import io.karma.evince.krypton.toBigNumber
import io.karma.evince.krypton.utils.ErrorHelper
import kotlinx.cinterop.CPointer
import libssl.*

actual class ParameterizedEllipticCurve actual constructor(
    private val parameters: EllipticCurveParameters
) : EllipticCurve {
    private val bnCtx: CPointer<BN_CTX> = requireNotNull(BN_CTX_new())
    private val cache: MutableList<CPointer<BIGNUM>> = mutableListOf()
    internal val curve: CPointer<EC_GROUP> = requireNotNull(
        when (val field = parameters.field) {
            is EllipticCurveParameters.Field.Fp -> EC_GROUP_new_curve_GFp(
                field.p.toBigNumber(cache),
                parameters.a.toBigNumber(cache),
                parameters.b.toBigNumber(cache),
                bnCtx
            )
        }
    )
    private val generator: CPointer<EC_POINT> = requireNotNull(EC_POINT_new(curve))

    init {
        val (x, y) = parameters.generatorPoint
        if (EC_POINT_set_affine_coordinates(curve, generator, x.toBigNumber(cache), y.toBigNumber(cache), bnCtx) != 1)
            throw RuntimeException(
                "Unable to set generator point of elliptic curve '${parameters.name}'",
                ErrorHelper.createOpenSSLException()
            )
        if (EC_GROUP_set_generator(curve, generator, parameters.order.toBigNumber(cache), null) != 1)
            throw RuntimeException(
                "Unable to set generator of elliptic curve '${parameters.name}'",
                ErrorHelper.createOpenSSLException()
            )
    }

    override fun close() {
        EC_POINT_free(generator)
        cache.forEach { BN_free(it) }
        BN_CTX_free(bnCtx)
    }

    override fun toString(): String = parameters.name
}

/** @suppress **/
inline fun DefaultEllipticCurve.toOpenSSLId(): Int = when(this) {
    DefaultEllipticCurve.PRIME192V1 -> NID_X9_62_prime192v1
    DefaultEllipticCurve.PRIME192V2 -> NID_X9_62_prime192v2
    DefaultEllipticCurve.PRIME192V3 -> NID_X9_62_prime192v3
    DefaultEllipticCurve.PRIME239V1 -> NID_X9_62_prime239v1
    DefaultEllipticCurve.PRIME239V2 -> NID_X9_62_prime239v2
    DefaultEllipticCurve.PRIME239V3 -> NID_X9_62_prime192v3
    DefaultEllipticCurve.PRIME256V1 -> NID_X9_62_prime256v1
    DefaultEllipticCurve.BRAINPOOL_P160T1 -> NID_brainpoolP160t1
    DefaultEllipticCurve.BRAINPOOL_P192T1 -> NID_brainpoolP192t1
    DefaultEllipticCurve.BRAINPOOL_P224T1 -> NID_brainpoolP224t1
    DefaultEllipticCurve.BRAINPOOL_P256T1 -> NID_brainpoolP256t1
    DefaultEllipticCurve.BRAINPOOL_P320T1 -> NID_brainpoolP320t1
    DefaultEllipticCurve.BRAINPOOL_P384T1 -> NID_brainpoolP384t1
    DefaultEllipticCurve.BRAINPOOL_P512T1 -> NID_brainpoolP512t1
    DefaultEllipticCurve.BRAINPOOL_P160R1 -> NID_brainpoolP160r1
    DefaultEllipticCurve.BRAINPOOL_P192R1 -> NID_brainpoolP192r1
    DefaultEllipticCurve.BRAINPOOL_P256R1 -> NID_brainpoolP256r1
    DefaultEllipticCurve.BRAINPOOL_P224R1 -> NID_brainpoolP224r1
    DefaultEllipticCurve.BRAINPOOL_P320R1 -> NID_brainpoolP320r1
    DefaultEllipticCurve.BRAINPOOL_P384R1 -> NID_brainpoolP384r1
    DefaultEllipticCurve.BRAINPOOL_P512R1 -> NID_brainpoolP512r1
}
