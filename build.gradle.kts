object Metadata {
    const val description = "Encryption/Decryption Wrapper And Provide Simple Usability."
    const val license = "MIT License"
    const val licenseUrl = "https://opensource.org/license/mit"
    const val githubRepo = "ppzxc/crypto"
    const val release = "https://s01.oss.sonatype.org/service/local/"
    const val snapshot = "https://s01.oss.sonatype.org/content/repositories/snapshots/"
}

plugins {
    `java-library`
    id("me.champeau.jmh") version "0.7.2"
    id("maven-publish")
    signing
}

group = "io.github.ppzxc"
version = "v0.0.15"

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

val repositories = arrayOf(
    "https://oss.sonatype.org/content/repositories/snapshots/",
    "https://s01.oss.sonatype.org/content/repositories/snapshots/"
)

repositories {
    mavenLocal()
    mavenCentral()
    repositories.forEach { maven(it) }
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
    val signingKey = providers
        .environmentVariable("GPG_SIGNING_KEY")
    val signingPassphrase = providers
        .environmentVariable("GPG_SIGNING_PASSPHRASE")

    if (signingKey.isPresent && signingPassphrase.isPresent) {
        useInMemoryPgpKeys(signingKey.get(), signingPassphrase.get())
        val extension = extensions
            .getByName("publishing") as PublishingExtension
        sign(extension.publications)
    }
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            groupId = project.group.toString()
            artifactId = project.name
            version = project.version.toString()

            pom {
                name = project.name
                description = Metadata.description
                url = "https://github.com/${Metadata.githubRepo}"

                licenses {
                    license {
                        name = Metadata.license
                        url = Metadata.licenseUrl
                    }
                }

                developers {
                    developer {
                        id = "ppzxc"
                        name = "JeongHa Cho"
                        email = "cjh8487@naver.com"
                    }
                }

                scm {
                    connection = "scm:git:git://github.com/${Metadata.githubRepo}.git"
                    developerConnection = "scm:git:ssh://github.com/${Metadata.githubRepo}.git"
                    url = "https://github.com/${Metadata.githubRepo}"
                }

                issueManagement {
                    url.set("https://github.com/${Metadata.githubRepo}/issues")
                }
            }
        }
    }
}