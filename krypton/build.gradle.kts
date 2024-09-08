import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotest)
    alias(libs.plugins.dokka)
}

group = "io.karma.evince"
version = "${libs.versions.krypton.get()}.${System.getenv("CI_PIPELINE_IID")?: 0}"

kotlin {
    @OptIn(ExperimentalKotlinGradlePluginApi::class)
    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }

    jvm {
        testRuns["test"].executionTask {
            useJUnitPlatform()
        }
    }
    linuxX64 {
        @OptIn(ExperimentalKotlinGradlePluginApi::class)
        compilerOptions {
            freeCompilerArgs.addAll(listOf("-linker-option", "--allow-shlib-undefined"))
        }

        compilations.all {
            cinterops {
                val libssl by creating
            }
        }
        binaries.sharedLib()
    }

    sourceSets {
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.bundles.kotest)
        }
        jvmTest.dependencies {
            implementation(libs.kotest.junit.runner)
        }
    }
}
