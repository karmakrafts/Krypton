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
    private val curve: CPointer<EC_GROUP> = requireNotNull(
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
