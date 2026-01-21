buildscript {
    repositories.mavenCentral()

    dependencies {
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.2.21")
    }
}

tasks.register<Delete>("clean") {
    delete = setOf("build")
}
