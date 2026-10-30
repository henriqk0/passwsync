# JNA and the generated UniFFI bindings are used through reflection.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class io.github.henriqk0.passwsync.core.** { *; }
