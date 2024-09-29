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

import io.karma.evince.krypton.Algorithm
import io.karma.evince.krypton.AsymmetricKey
import io.karma.evince.krypton.GeneratorException
import io.karma.evince.krypton.InitializationException
import io.karma.evince.krypton.Key
import io.karma.evince.krypton.Keypair
import io.karma.evince.krypton.OpenSSLException
import io.karma.evince.krypton.annotations.InternalKryptonAPI
import io.karma.evince.krypton.forType
import io.karma.evince.krypton.from
import io.karma.evince.krypton.internal.openssl.EVP_PKEY
import io.karma.evince.krypton.internal.openssl.EVP_PKEY_CTX
import io.karma.evince.krypton.internal.openssl.EVP_PKEY_CTX_free
import io.karma.evince.krypton.internal.openssl.EVP_PKEY_CTX_new_id
import io.karma.evince.krypton.internal.openssl.EVP_PKEY_dup
import io.karma.evince.krypton.internal.openssl.EVP_PKEY_keygen
import io.karma.evince.krypton.internal.openssl.EVP_PKEY_keygen_init
import io.karma.evince.krypton.parameters.KeypairGeneratorParameters
import io.karma.evince.krypton.utils.WithFree
import io.karma.evince.krypton.utils.checkNotNull
import io.karma.evince.krypton.utils.withFreeWithException
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.allocPointerTo
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value

@InternalKryptonAPI
internal inline fun <reified P : KeypairGeneratorParameters> internalGenerateKeypair(
    algorithm: Algorithm,
    crossinline contextGenerator: WithFree.(P) -> CPointer<EVP_PKEY_CTX>?,
    crossinline contextConfigurator: (CPointer<EVP_PKEY_CTX>, P) -> Unit,
    parameters: KeypairGeneratorParameters
): Keypair {
    if (parameters !is P) {
        throw InitializationException("Invalid parameter type '${parameters::class.qualifiedName}'")
    }

    return withFreeWithException {
        val generatorContext = contextGenerator(parameters).checkNotNull().freeAfter(::EVP_PKEY_CTX_free)
        if (EVP_PKEY_keygen_init(generatorContext) != 1) {
            throw GeneratorException("Unable to init keypair generator", OpenSSLException.create())
        }
        contextConfigurator(generatorContext, parameters)

        val key = memScoped {
            val keyPointer = allocPointerTo<EVP_PKEY>()
            if (EVP_PKEY_keygen(generatorContext, keyPointer.ptr) != 1) {
                throw GeneratorException("Unable to generate private key", OpenSSLException.create())
            }
            keyPointer.value.checkNotNull()
        }

        Keypair.from(
            AsymmetricKey(Key.Type.PRIVATE, algorithm, parameters.usages.forType(Key.Type.PRIVATE), EVP_PKEY_dup(key).checkNotNull()),
            AsymmetricKey(Key.Type.PUBLIC, algorithm, parameters.usages.forType(Key.Type.PUBLIC), key)
        )
    }
}

@InternalKryptonAPI
internal inline fun <reified P : KeypairGeneratorParameters> internalGenerateKeypairWithNid(
    nid: Int,
    algorithm: Algorithm,
    crossinline contextConfigurator: (CPointer<EVP_PKEY_CTX>, P) -> Unit,
    parameters: KeypairGeneratorParameters
) = internalGenerateKeypair(
    algorithm = algorithm,
    contextGenerator = { EVP_PKEY_CTX_new_id(nid, null) },
    contextConfigurator = contextConfigurator,
    parameters = parameters
)
