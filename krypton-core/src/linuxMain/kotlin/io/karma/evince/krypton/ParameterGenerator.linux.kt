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

import io.karma.evince.krypton.annotations.InternalKryptonAPI
import io.karma.evince.krypton.internal.params.InternalParameterGenerator
import io.karma.evince.krypton.internal.params.InternalParameterGeneratorRegistry
import io.karma.evince.krypton.key.KeyPairGeneratorParameters

/**
 * @author Cedric Hammes
 * @since  18/09/2024
 * @suppress
 */
@OptIn(InternalKryptonAPI::class)
actual class ParameterGenerator actual constructor(
    algorithm: String,
    parameters: ParameterGeneratorParameters
) : AutoCloseable {
    private val internal: InternalParameterGenerator =
        InternalParameterGeneratorRegistry.createGenerator(algorithm, parameters)
    
    actual constructor(algorithm: Algorithm, parameters: ParameterGeneratorParameters) :
            this(algorithm.checkScopeOrError(Algorithm.Scope.PARAMETER_GENERATOR).toString(), parameters)
    
    actual fun generate(): KeyPairGeneratorParameters = this.internal.generate()
    actual override fun close() = this.internal.close()
}
