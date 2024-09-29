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

/**
 * This exception is thrown if a unspecific error occurs while working with the Krypton cryptography API and it's components. Most of the
 * exceptions are specific for the case but a few are this type.
 *
 * @author Cedric Hammes
 * @since  29/09/2024
 */
open class KryptonException internal constructor(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/**
 * This exception is thrown if a error occurs while initializing a component or a temporary generator etc. On Native targets, the cause is
 * an OpenSSL exception with all errors extracted from OpenSSL.
 *
 * @author Cedric Hammes
 * @since  29/09/2024
 */
class InitializationException internal constructor(message: String, cause: Throwable? = null) : KryptonException(message, cause)

/**
 * This exception is thrown if a error occurs while operating with a cipher after the initialisation step. On Native targets, the cause is
 * an OpenSSL exception with all errors extracted from OpenSSL.
 *
 * @author Cedric Hammes
 * @since  29/09/2024
 */
class CipherException internal constructor(message: String, cause: Throwable? = null) : KryptonException(message, cause)

/**
 * This exception is thrown if a error occurs while operating with a key generator or keypair generator after the initialization step. On
 * Native targets, the cause is an OpenSSL exception with all errors extracted from PpenSSL.
 *
 * @author Cedric Hammes
 * @since  29/09/2024
 */
class GeneratorException internal constructor(message: String, cause: Throwable? = null) : KryptonException(message, cause)
