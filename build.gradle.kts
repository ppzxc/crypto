plugins {
    `java-library`
    `maven-publish`
    signing
    id("me.champeau.jmh") version "0.7.2"
    id("io.github.gradle-nexus.publish-plugin") version "1.3.0"
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
    val signingKey = providers.environmentVariable("GPG_SIGNING_KEY")
    val signingPassphrase = providers.environmentVariable("GPG_SIGNING_PASSPHRASE")

    if (signingKey.isPresent && signingPassphrase.isPresent) {
        useInMemoryPgpKeys(signingKey.get(), signingPassphrase.get())
        val extension = extensions.getByName("publishing") as PublishingExtension
        sign(extension.publications)
    }
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            groupId = providers.gradleProperty("GROUP_NAME").get()
            artifactId = providers.gradleProperty("ARTIFACT_NAME").get()
            version = providers.gradleProperty("VERSION_NAME").get()

            pom {
                name = providers.gradleProperty("ARTIFACT_NAME").get()
                description = providers.gradleProperty("POM_DESCRIPTION").get()
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

                issueManagement {
                    url = providers.gradleProperty("POM_ISSUE_MANAGEMENT_URL").get()
                }
            }
        }
    }
}

nexusPublishing {
    repositories {
        sonatype {  //only for users registered in Sonatype after 24 Feb 2021
            nexusUrl.set(uri("https://s01.oss.sonatype.org/service/local/"))
            snapshotRepositoryUrl.set(uri("https://s01.oss.sonatype.org/content/repositories/snapshots/"))
        }
    }
}