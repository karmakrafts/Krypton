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

package io.karma.evince.krypton.impl

import io.karma.evince.krypton.annotations.InternalKryptonAPI
import io.karma.evince.krypton.internal.openssl.EVP_PKEY
import io.karma.evince.krypton.internal.openssl.EVP_PKEY_CTX
import io.karma.evince.krypton.internal.openssl.EVP_PKEY_CTX_new_id
import io.karma.evince.krypton.internal.openssl.EVP_PKEY_paramgen
import io.karma.evince.krypton.internal.openssl.EVP_PKEY_paramgen_init
import io.karma.evince.krypton.parameters.Parameters
import io.karma.evince.krypton.utils.WithFree
import io.karma.evince.krypton.utils.checkNotNull
import io.karma.evince.krypton.utils.withFreeWithException
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.allocPointerTo
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value

@InternalKryptonAPI
fun <T : Parameters> nidParameterGenerator(
    nid: Int,
    configurator: (CPointer<EVP_PKEY_CTX>) -> Unit,
    outputFactory: WithFree.(CPointer<EVP_PKEY>) -> T
): T = withFreeWithException {
    val parameterGenerator = EVP_PKEY_CTX_new_id(nid, null).checkNotNull()
    if (EVP_PKEY_paramgen_init(parameterGenerator) != 1)
        throw RuntimeException("Unable to initialize parameter generator")
    configurator(parameterGenerator)

    memScoped {
        val parametersPtr = allocPointerTo<EVP_PKEY>()
        if (EVP_PKEY_paramgen(parameterGenerator, parametersPtr.ptr) != 1)
            throw RuntimeException("Unable to generate parameters")
        outputFactory(parametersPtr.value.checkNotNull())
    }
}
