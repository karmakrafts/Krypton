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

package io.karma.evince.krypton.annotations

/**
 * This annotation is marking an unstable API interface or algorithm of the Krypton library. These algorithms can be not
 * standardized by NIST etc. APIs can not be stabilized for the next release. Mostly functions added before the release
 * are marked unstable until the API is released.
 *
 * These APIs are ready to use for the user but can be removed in the next release and are not recommended to use if you
 * develop a future-versions proofed application.
 *
 * @author Cedric Hammes
 * @since  26/09/2024
 */
@Retention(AnnotationRetention.BINARY)
@RequiresOptIn(level = RequiresOptIn.Level.WARNING, message = "This API is unstable and can be removed/changed in the next version")
annotation class UnstableKryptonAPI
