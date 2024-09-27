dependencyResolutionManagement {
    repositories {
        mavenCentral()
        google()
        maven("https://s01.oss.sonatype.org/content/repositories/snapshots/") {
            name = "MavenCentralSnapshots"
            mavenContent { snapshotsOnly() }
        }
    }
}

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
        google()
        maven("https://s01.oss.sonatype.org/content/repositories/snapshots/") {
            name = "MavenCentralSnapshots"
            mavenContent { snapshotsOnly() }
        }
    }
}

include(":krypton")
rootProject.name = "krypton"
