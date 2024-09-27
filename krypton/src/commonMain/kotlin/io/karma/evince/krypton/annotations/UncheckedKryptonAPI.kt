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
 * This annotation is marking an unchecked API interface of the Krypton library. These APIs can be used by the user to
 * use not-officially supported algorithms or platform-dependant algorithms etc. Please prefer other APIs other these
 * unchecked APIs.
 *
 * @author Cedric Hammes
 * @since  08/09/2024
 */
@Retention(AnnotationRetention.BINARY)
@RequiresOptIn(level = RequiresOptIn.Level.WARNING, message = "This API does not ensure the correctness of the input")
annotation class UncheckedKryptonAPI
