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

internal expect fun determinePlatform(): Platform

enum class Platform {
    MINGW_X64,
    LINUX_X64,
    MACOS_X64,
    MACOS_ARM64,
    IOS_X64,
    IOS_ARM64,
    BROWSER,
    NODE,
    JVM;

    fun isWeb(): Boolean = this == NODE || this == BROWSER

    companion object {
        val CURRENT: Platform = determinePlatform()
        val IS_BROWSER: Boolean = CURRENT == BROWSER
    }
}
