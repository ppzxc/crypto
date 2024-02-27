plugins {
    `java-library`
    signing
    id("net.thebugmc.gradle.sonatype-central-portal-publisher") version "1.1.1"
}

group = providers.gradleProperty("GROUP_NAME").get()
version = providers.gradleProperty("VERSION_NAME").get()

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

repositories {
    mavenCentral()
}

dependencies {
    jmh("org.openjdk.jmh:jmh-core:1.37")
    jmh("org.openjdk.jmh:jmh-generator-annprocess:1.37")
    jmh("org.openjdk.jmh:jmh-generator-bytecode:1.37")
    jmhAnnotationProcessor("org.openjdk.jmh:jmh-generator-annprocess:1.37")

    implementation("org.bouncycastle:bcprov-jdk18on:1.77")
    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.assertj:assertj-core:3.25.3")
}

tasks.withType<Test> {
    useJUnitPlatform()
}

java {
    withSourcesJar()
    withJavadocJar()
}

artifacts {
    archives(tasks.named("javadocJar"))
    archives(tasks.named("sourcesJar"))
}

signing {
//    val signingKey = providers.environmentVariable("GPG_SIGNING_KEY")
    val signingKey = """
        -----BEGIN PGP PRIVATE KEY BLOCK-----

        lIYEZd1yjRYJKwYBBAHaRw8BAQdAklsVjyBRYHHRaxMU55pNHUU5Q78um9iKt0b7
        IvsjGw/+BwMCGUURIafvs/Du83N7yI+9rEQQfwvHuX9W4W3/bzWYYjmgjJENScZD
        Yg0FCmAS3WkmFoxUopCX05WsmdxMsLaThcAUlvvMjoZ/QLoQNeobyrQZcHB6eGMg
        PGNqaDg0ODdAbmF2ZXIuY29tPoiZBBMWCgBBFiEEKv/S0IpLwYc2TSUaAZQafitW
        wTIFAmXdco0CGwMFCQWkyaMFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQ
        AZQafitWwTJsggD/YszcnNHSzriOJ5JKtLcZb0Yq9DuObP7v1zuMWYFE6D8A/3B8
        IC8eB3RqUuom4ysYggK+BYlsJtIMGsJatWvVmFACnIsEZd1yjRIKKwYBBAGXVQEF
        AQEHQAZRNiGRhXgLLnwKM2Zo4oB7ygUBw8XN1WHrcCHSC41hAwEIB/4HAwJYouov
        JWT+mO77JJ4LQv0NOibJnytqsb2/xXGisjmLEPWK87KdzAqoH9txhIYMNkLq+zu/
        pzpohPnQmqq5TeLXI5LIFjMIZgtZD7O8xrRNiH4EGBYKACYWIQQq/9LQikvBhzZN
        JRoBlBp+K1bBMgUCZd1yjQIbDAUJBaTJowAKCRABlBp+K1bBMnXjAP9tD4bKaqTw
        ee24G4IPADxbr7J3XQihgkA9R5ORfc0IggD/UPZUSyx6aqlJsNAJGMGoMtR1Z65Z
        ohpGAaAwTaVoMAw=
        =vlkt
        -----END PGP PRIVATE KEY BLOCK-----
    """.trimIndent()
//    val signingPassphrase = providers.environmentVariable("GPG_SIGNING_PASSPHRASE")
    val signingPassphrase = "asdf851216"

//    if (signingKey.isPresent && signingPassphrase.isPresent) {
    useInMemoryPgpKeys(signingKey, signingPassphrase)
    val extension = extensions.getByName("publishing") as PublishingExtension
    sign(extension.publications)
//    }
}

centralPortal {
    username = "0wr4f6mf"
    password = "8xOqwiPfZREm4uW4x5eY/kJ2jK7YUqyJ5JtMb3qAH2RN"
    pom {
        group = providers.gradleProperty("GROUP_NAME").get()
        name = providers.gradleProperty("ARTIFACT_NAME").get()
        description = providers.gradleProperty("POM_DESCRIPTION").get()
        packaging = "jar"
        // `name = project.name`, `description = project.description` and `packaging = "jar"`
        // are applied automatically, but you can override them here
        url = providers.gradleProperty("POM_URL").get()
        licenses {
            license {
                name = providers.gradleProperty("POM_LICENSE_NAME").get()
                url = providers.gradleProperty("POM_LICENSE_URL").get()
            }
        }
        developers {
            developer {
                id = providers.gradleProperty("POM_DEVELOPER_ID").get()
                name = providers.gradleProperty("POM_DEVELOPER_NAME").get()
                email = providers.gradleProperty("POM_DEVELOPER_EMAIL").get()
                url = providers.gradleProperty("POM_DEVELOPER_URL").get()
            }
        }
        scm {
            url = providers.gradleProperty("POM_SCM_URL").get()
            connection = providers.gradleProperty("POM_SCM_CONNECTION").get()
            developerConnection = providers.gradleProperty("POM_SCM_DEV_CONNECTION").get()
        }
    }
}


//publishing {
//    publications {
//        create<MavenPublication>("mavenJava") {
//            groupId = providers.gradleProperty("GROUP_NAME").get()
//            artifactId = providers.gradleProperty("ARTIFACT_NAME").get()
//            version = providers.gradleProperty("VERSION_NAME").get()
//
//            pom {
//                name = providers.gradleProperty("ARTIFACT_NAME").get()
//                description = providers.gradleProperty("POM_DESCRIPTION").get()
//                url = providers.gradleProperty("POM_URL").get()
//
//                licenses {
//                    license {
//                        name = providers.gradleProperty("POM_LICENSE_NAME").get()
//                        url = providers.gradleProperty("POM_LICENSE_URL").get()
//                    }
//                }
//
//                developers {
//                    developer {
//                        id = providers.gradleProperty("POM_DEVELOPER_ID").get()
//                        name = providers.gradleProperty("POM_DEVELOPER_NAME").get()
//                        email = providers.gradleProperty("POM_DEVELOPER_EMAIL").get()
//                        url = providers.gradleProperty("POM_DEVELOPER_URL").get()
//                    }
//                }
//
//                scm {
//                    url = providers.gradleProperty("POM_SCM_URL").get()
//                    connection = providers.gradleProperty("POM_SCM_CONNECTION").get()
//                    developerConnection = providers.gradleProperty("POM_SCM_DEV_CONNECTION").get()
//                }
//
//                issueManagement {
//                    url = providers.gradleProperty("POM_ISSUE_MANAGEMENT_URL").get()
//                }
//            }
//        }
//    }
//}

//nexusPublishing {
//    repositories {
////        sonartype()
//        sonatype {  //only for users registered in Sonatype after 24 Feb 2021
//            nexusUrl.set(uri("https://central.sonatype.com/service/local/staging/deploy/maven2/"))
////            nexusUrl.set(uri("https://s01.oss.sonatype.org/service/local/"))
//            snapshotRepositoryUrl.set(uri("https://central.sonatype.com/content/repositories/snapshots/"))
//            username = "0wr4f6mf"
//            password = "8xOqwiPfZREm4uW4x5eY/kJ2jK7YUqyJ5JtMb3qAH2RN"
//        }
//    }
//}

//publishing {
//    repositories {
//        maven {
//            name = "local"
//            // change URLs to point to your repos, e.g. http://my.org/repo
//            releasesRepoUrl = "$buildDir/repos/releases"
//            snapshotsRepoUrl = "$buildDir/repos/snapshots"
//            url = version.endsWith("SNAPSHOT") ? snapshotsRepoUrl : releasesRepoUrl
//        }
//    }
//}