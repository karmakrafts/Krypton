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
 * This annotation is marking an internal undocumented API interface of the Krypton library. These APIs should not be
 * used by an external developer. These APIs are only set public for the development of Krypton modules like the
 * PQ-crypto module.
 *
 * @author Cedric Hammes
 * @since  08/09/2024
 */
@Retention(AnnotationRetention.BINARY)
@RequiresOptIn(level = RequiresOptIn.Level.ERROR, message = "This API is only intended for Krypton modules")
annotation class InternalKryptonAPI
