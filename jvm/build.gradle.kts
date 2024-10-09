import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.asRequestBody
import jetbrains.sign.GpgSignSignatoryProvider
import java.util.*

val kotlinVersion = "1.9.22"
val junitVersion = "5.8.2"
val mockitoVersion = "4.2.0"
val isUnderTeamCity = System.getenv("TEAMCITY_VERSION") != null

version = rootProject.ext.get("projectVersion") as String

buildscript {
    repositories {
        maven { url = uri("https://packages.jetbrains.team/maven/p/jcs/maven") }
    }
    dependencies {
        classpath("com.jetbrains:jet-sign:45.55")
        classpath("com.squareup.okhttp3:okhttp:4.12.0")
    }
}

plugins {
    kotlin("jvm") version "1.9.22"
    signing
    `maven-publish`
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
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
    implementation("org.bouncycastle:bcutil-jdk18on:1.78.1")
    implementation("org.jetbrains.kotlin:kotlin-stdlib:$kotlinVersion")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-jdk8:1.7.3")
    implementation("org.apache.commons:commons-compress:1.26.1")

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
    withJavadocJar()
    withSourcesJar()
}

publishing {
    repositories {
        maven {
            name = "artifacts"
            url = uri(layout.buildDirectory.dir("artifacts/maven"))
        }
    }

    publications {
        create<MavenPublication>("mavenJava") {
            artifactId = "format-ripper"
            group = "com.jetbrains.format-ripper"
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

                organization {
                    name.set("JetBrains s.r.o.")
                    url.set("https://www.jetbrains.com/")
                }

                developers {
                    developer {
                        id.set("mikhail.pilin")
                        name.set("Mikhail Pilin")
                        email.set("mikhail.pilin@jetbrains.com")
                    }
                    developer {
                        id.set("konstantin.kretov")
                        name.set("Konstantin Kretov")
                        email.set("konstantin.kretov@jetbrains.com")
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

if (isUnderTeamCity) {
    signing {
        sign(publishing.publications)
        signatories = GpgSignSignatoryProvider()
    }
}

tasks {
    val packSonatypeCentralBundle by registering(Zip::class) {
        group = "publishing"

        dependsOn(":publishMavenJavaPublicationToArtifactsRepository")

        from(layout.buildDirectory.dir("artifacts/maven"))
        archiveFileName.set("bundle.zip")
        destinationDirectory.set(layout.buildDirectory)
    }

    val publishMavenToCentralPortal by registering {
        group = "publishing"

        dependsOn(packSonatypeCentralBundle)

        doLast {
            val uriBase = "https://central.sonatype.com/api/v1/publisher/upload"
            val publicationType = "USER_MANAGED"
            val deploymentName = "${project.name}-$version"
            val uri = "$uriBase?name=$deploymentName&publicationType=$publicationType"

            val userName = rootProject.extra["centralPortalUserName"] as String
            val token = rootProject.extra["centralPortalToken"] as String
            val base64Auth = Base64.getEncoder().encode("$userName:$token".toByteArray()).toString(Charsets.UTF_8)
            val bundleFile = packSonatypeCentralBundle.get().archiveFile.get().asFile

            println("Sending request to $uri...")

            val client = OkHttpClient()
            val request = Request.Builder()
                .url(uri)
                .header("Authorization", "Bearer $base64Auth")
                .post(
                    MultipartBody.Builder()
                        .setType(MultipartBody.FORM)
                        .addFormDataPart("bundle", bundleFile.name, bundleFile.asRequestBody())
                        .build()
                )
                .build()
            val response = client.newCall(request).execute()

            val statusCode = response.code
            println("Upload status code: $statusCode")
            println("Upload result: ${response.body!!.string()}")
            if (statusCode != 201) {
                error("Upload error to Central repository. Status code $statusCode.")
            }
        }
    }
}