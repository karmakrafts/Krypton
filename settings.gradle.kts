dependencyResolutionManagement {
    repositories {
        mavenCentral()
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
        maven("https://s01.oss.sonatype.org/content/repositories/snapshots/") {
            name = "MavenCentralSnapshots"
            mavenContent { snapshotsOnly() }
        }
    }
}

include(":krypton")
rootProject.name = "krypton"
