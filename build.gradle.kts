plugins {
    `java-library`
    signing
    id("net.thebugmc.gradle.sonatype-central-portal-publisher") version "1.2.2"
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
    val signingKey = System.getenv("GPG_SIGNING_KEY") as String
    val signingPassphrase = System.getenv("GPG_SIGNING_PASSPHRASE") as String

    useInMemoryPgpKeys(signingKey, signingPassphrase)
    val extension = extensions.getByName("publishing") as PublishingExtension
    sign(extension.publications)
}

centralPortal {
    username = System.getenv("OSSRH_USERNAME") as String
    password = System.getenv("OSSRH_PASSWORD") as String
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