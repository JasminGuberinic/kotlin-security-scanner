// Ktor specific rules — missing authentication, insecure session cookies, permissive CORS.
// Depends on scanner-core for shared base classes and patterns.

dependencies {
    implementation(project(":scanner-core"))
}
