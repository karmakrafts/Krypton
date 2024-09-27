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

package io.karma.evince.krypton.platform

// https://github.com/ktorio/ktor/blob/6ab2a63747a5c0d58c882155b905a3601f5927cd/ktor-utils/jsAndWasmShared/src/io/ktor/util/PlatformUtilsJs.kt#L14-L24
private fun hasNodeApi(): Boolean = js(
    """
(typeof process !== 'undefined' 
    && process.versions != null 
    && process.versions.node != null) ||
(typeof window !== 'undefined' 
    && typeof window.process !== 'undefined' 
    && window.process.versions != null 
    && window.process.versions.node != null)
"""
) as Boolean

internal actual fun determinePlatform(): Platform =
    if (hasNodeApi()) Platform.NODE else Platform.BROWSER