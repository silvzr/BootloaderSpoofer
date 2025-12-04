# Keep the Xposed module entry and hookers so their names and signatures stay intact
-keep class es.chiteroman.bootloaderspoofer.BootloaderSpooferModule { *; }
-keep class es.chiteroman.bootloaderspoofer.** implements io.github.libxposed.api.XposedInterface$Hooker { *; }
-keepclassmembers class es.chiteroman.bootloaderspoofer.** implements io.github.libxposed.api.XposedInterface$Hooker {
    public static <methods>;
}
# Do not repackage; keep package names stable for LSPosed discovery
-dontobfuscate
-dontoptimize