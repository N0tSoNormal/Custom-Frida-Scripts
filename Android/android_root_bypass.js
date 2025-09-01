Java.perform(function () {
    var RootPackages = [
        "com.noshufou.android.su",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.topjohnwu.magisk"
    ];

    var RootBinaries = [
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/system/su",
        "/system/bin/.ext/su",
        "/system/usr/we-need-root/su",
        "/system/app/Superuser.apk",
        "/system/app/SuperSU.apk"
    ];

    var RootProps = {
        "ro.debuggable": "0",
        "ro.secure": "1"
    };

    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (p, f) {
        if (RootPackages.indexOf(p) >= 0) {
            throw new Error("Package not found: " + p);
        }
        return this.getPackageInfo(p, f);
    };

    var File = Java.use("java.io.File");
    File.exists.implementation = function () {
        var name = this.getAbsolutePath();
        if (RootBinaries.indexOf(name) >= 0) {
            return false;
        }
        return this.exists();
    };

    var SystemProperties = Java.use("android.os.SystemProperties");
    SystemProperties.get.overload('java.lang.String').implementation = function (name) {
        if (RootProps.hasOwnProperty(name)) {
            return RootProps[name];
        }
        return this.get(name);
    };

    console.log("[*] Root detection bypass applied");
});