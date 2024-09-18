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

package io.karma.evince.krypton.internal.params

import io.karma.evince.krypton.ParameterGeneratorParameters
import io.karma.evince.krypton.annotations.InternalKryptonAPI
import io.karma.evince.krypton.key.DHKeyPairGeneratorParameters
import io.karma.evince.krypton.key.KeyPairGeneratorParameters
import io.karma.evince.krypton.utils.*
import io.karma.evince.krypton.utils.ErrorHelper
import io.karma.evince.krypton.utils.checkNotNull
import io.karma.evince.krypton.utils.withFree
import kotlinx.cinterop.*
import libssl.*

/** @suppress **/
@InternalKryptonAPI
open class OpenSSLParameterGenerator(
    nid: Int,
    configurator: (CPointer<EVP_PKEY_CTX>) -> Unit,
    private val outputFactory: WithFree.(CPointer<EVP_PKEY>) -> KeyPairGeneratorParameters
) : InternalParameterGenerator {
    private val parameterGenerator: CPointer<EVP_PKEY_CTX> = EVP_PKEY_CTX_new_id(nid, null).checkNotNull()
    private val generatedParameters: CPointerVar<EVP_PKEY> = nativeHeap.allocPointerTo<EVP_PKEY>().checkNotNull()
    
    init {
        if (EVP_PKEY_paramgen_init(parameterGenerator) != 1)
            throw RuntimeException("Unable to initialize parameter generator")
        configurator(parameterGenerator)
    }
    
    override fun generate(): KeyPairGeneratorParameters = withFree {
        val parameters = EVP_PKEY_new().checkNotNull().freeAfter(::EVP_PKEY_free)
        memScoped {
            val parametersPtr = allocPointerTo<EVP_PKEY>()
            parametersPtr.value = parameters
            if (EVP_PKEY_paramgen(parameterGenerator, parametersPtr.ptr) != 1)
                throw RuntimeException("Unable to generate parameters")
        }
        outputFactory(parameters)
    }
    
    override fun close() {
        EVP_PKEY_free(generatedParameters.value)
        nativeHeap.free(generatedParameters)
        EVP_PKEY_CTX_free(parameterGenerator)
    }
}

/** @suppress **/
@InternalKryptonAPI
internal class DHOpenSSLParameterGenerator(parameters: ParameterGeneratorParameters) : OpenSSLParameterGenerator(
    nid = EVP_PKEY_DH,
    configurator = { generator ->
        if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(generator, parameters.bits) != 1)
            throw RuntimeException("Unable to set prime length")
    },
    outputFactory = { rawParameters ->
        val dhParameters = EVP_PKEY_get1_DH(rawParameters).checkNotNull().freeAfter(::DH_free)
        DHKeyPairGeneratorParameters(
            DH_get0_p(dhParameters).checkNotNull().toBigInteger(),
            DH_get0_g(dhParameters).checkNotNull().toBigInteger(),
            parameters.bits
        )
    }
)
