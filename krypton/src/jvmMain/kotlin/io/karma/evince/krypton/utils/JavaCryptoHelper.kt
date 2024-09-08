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

package io.karma.evince.krypton.utils

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
import java.security.Provider
import java.security.Security

/** @suppress **/
internal object JavaCryptoHelper {
    internal inline fun <reified T> getAlgorithms(): List<String> = Security.getProviders()
        .flatMap { it.services.filter { service -> service.type.equals(T::class.simpleName) } }
        .map { it.algorithm }.toList()

    internal fun installBouncyCastleProviders() {
        // https://www.bouncycastle.org/documentation/specification_interoperability/
        installIfNotFound(BouncyCastleProvider())
        installIfNotFound(BouncyCastlePQCProvider())
    }

    private inline fun <reified T: Provider> installIfNotFound(value: T) {
        if (Security.getProviders().none { T::class.isInstance(it) })
            Security.addProvider(value)
    }
}
