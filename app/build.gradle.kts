repositories.mavenCentral()

plugins {
    kotlin("jvm")
}

tasks.register<JavaExec>("run") {
    classpath = sourceSets["main"].runtimeClasspath
    mainClass = "test.kotlin.bip32.AppKt"
}

dependencies {
    // todo
}
