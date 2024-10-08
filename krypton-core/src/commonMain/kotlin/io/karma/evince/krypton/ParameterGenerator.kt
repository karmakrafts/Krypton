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

import io.karma.evince.krypton.annotations.UncheckedKryptonAPI
import io.karma.evince.krypton.key.KeyPairGeneratorParameters

/**
 * This class is the parameter generator. The parameter generator is used to generate secure parameters for procedures
 * like key agreements. Currently only Diffie-Hellman is supported.
 *
 * @author Cedric Hammes
 * @since  18/09/2024
 */
expect class ParameterGenerator @UncheckedKryptonAPI constructor(
    algorithm: String,
    parameters: ParameterGeneratorParameters
) {
    constructor(algorithm: Algorithm, parameters: ParameterGeneratorParameters)
    
    fun generate(): KeyPairGeneratorParameters
}

/**
 * @author Cedric Hammes
 * @since  18/09/2024
 */
open class ParameterGeneratorParameters(internal val bits: Int)
