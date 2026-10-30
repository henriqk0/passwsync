# JNA and the generated UniFFI bindings are used through reflection (G7).
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class io.github.henriqk0.passwsync.core.** { *; }
-dontwarn java.awt.**
