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

import kotlin.jvm.JvmStatic

internal expect fun currentPlatform(): Platform

internal enum class Platform(private val literal: String) {
    OPENSSL("OpenSSL"),
    JVM("JVM"),
    BROWSER("Browser"),
    NODEJS("NodeJS");

    fun isJS(): Boolean = CURRENT == BROWSER || CURRENT == NODEJS
    override fun toString(): String = literal

    companion object {
        @JvmStatic
        val CURRENT: Platform = currentPlatform()
    }
}
