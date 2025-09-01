// Android Root Detection Bypass
Java.perform(function() {
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var name = this.getAbsolutePath();
        if (name.indexOf("su") !== -1 || name.indexOf("magisk") !== -1) {
            console.log("[!] Root check blocked: " + name);
            return false;
        }
        return this.exists();
    };

    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmd) {
        console.log("[!] Blocking Runtime.exec: " + cmd);
        return null;
    };
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        console.log("[!] Blocking Runtime.exec: " + cmd);
        return null;
    };

    var System = Java.use("java.lang.System");
    System.getenv.overload('java.lang.String').implementation = function(name) {
        if (name === "PATH") {
            console.log("[*] PATH check bypassed");
            return "";
        }
        return this.getenv(name);
    };
});