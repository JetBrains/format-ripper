import jetbrains.sign.GpgSignSignatoryProvider

val kotlinVersion = "1.8.21"
val junitVersion = "5.8.2"
val mockitoVersion = "4.2.0"
val isUnderTeamCity = System.getenv("TEAMCITY_VERSION") != null

buildscript {
    repositories {
        maven { url = uri("https://packages.jetbrains.team/maven/p/jcs/maven") }
    }
    dependencies {
        classpath("com.jetbrains:jet-sign:45.55")
    }
}

plugins {
    kotlin("jvm") version "1.8.21"
    signing
    `maven-publish`
    id("io.github.gradle-nexus.publish-plugin") version "1.1.0"
    kotlin("plugin.serialization") version "1.8.21"
}

sourceSets.main {
    resources.srcDirs(/*"src/main/resources/",*/ "../cert/") // Note(ww898): Please uncomment if you need standart resources in project
}

repositories {
    mavenCentral()
    gradlePluginPortal()
    maven { url = uri("https://packages.jetbrains.team/maven/p/jcs/maven") }
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk15on:1.70")
    implementation("org.bouncycastle:bcpkix-jdk15on:1.70")
    implementation("org.bouncycastle:bcutil-jdk15on:1.70")
    implementation("org.jetbrains.kotlin:kotlin-stdlib:$kotlinVersion")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.6.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-jdk8:1.6.0")
    implementation("org.apache.commons:commons-compress:1.21")
    implementation("com.google.code.gson:gson:2.10.1")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.5.1")

    testImplementation("org.junit.jupiter:junit-jupiter-params:$junitVersion")
    testImplementation("org.junit.jupiter:junit-jupiter-api:$junitVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitVersion")
    testCompileOnly("org.mockito:mockito-core:$mockitoVersion")
    testImplementation("org.mockito:mockito-junit-jupiter:$mockitoVersion")
}

tasks.test {
    useJUnitPlatform()
}

java {
    if (isUnderTeamCity) {
        withJavadocJar()
        withSourcesJar()
    }
}

if (isUnderTeamCity) {
    nexusPublishing {
        repositories {
            sonatype {
                username.set(rootProject.extra["sonatypeUser"].toString())
                password.set(rootProject.extra["sonatypePassword"].toString())
            }
        }
    }

    publishing {
        publications {
            create<MavenPublication>("mavenJava") {
                artifactId = "format-ripper"
                group = "com.jetbrains.format-ripper"
                version = rootProject.ext.get("projectVersion") as String
                from(components["java"])
                pom {
                    packaging = "jar"
                    name.set("JetBrains Format Ripper")
                    url.set("https://github.com/JetBrains/format-ripper")
                    description.set("A file format ripper library: provide info about binaries, perform cryptographic check")

                    licenses {
                        license {
                            name.set("The Apache License, Version 2.0")
                            url.set("https://www.apache.org/licenses/LICENSE-2.0")
                        }
                    }

                    developers {
                        developer {
                            id.set("anton.vladimirov")
                            name.set("Anton Vladimirov")
                            email.set("anton.vladimirov@jetbrains.com")
                        }
                    }

                    scm {
                        connection.set("scm:git@github.com:JetBrains/format-ripper.git")
                        url.set("https://github.com/JetBrains/format-ripper.git")
                    }
                }
            }
        }
    }

    signing {
        sign(publishing.publications)
        signatories = GpgSignSignatoryProvider()
    }
}