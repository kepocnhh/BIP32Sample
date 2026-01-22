repositories.mavenCentral()

plugins {
    kotlin("jvm")
}

tasks.register<JavaExec>("run") {
    classpath = sourceSets["main"].runtimeClasspath
    mainClass = "test.kotlin.bip32.AppKt"
}

dependencies {
    implementation("com.github.kepocnhh:Bytes:0.4.0")
}
