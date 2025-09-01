Java.perform(function () {
    console.log("[*] N0tSoNormal Custom Android Emulator Detection Bypass Loaded");

    var Build = Java.use("android.os.Build");

    Build.FINGERPRINT.value = "google/walleye/walleye:12/SP2A.220505.002/8353555:user/release-keys";
    Build.MODEL.value = "Pixel 2";
    Build.MANUFACTURER.value = "Google";
    Build.BRAND.value = "google";
    Build.DEVICE.value = "walleye";
    Build.PRODUCT.value = "walleye";
    Build.BOARD.value = "walleye";
    Build.HARDWARE.value = "walleye";
    Build.HOST.value = "host";
    Build.TAGS.value = "release-keys";

    console.log("[+] Patched Build properties");

    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");
        TelephonyManager.getNetworkOperatorName.implementation = function () {
            return "Vodafone";
        };
        TelephonyManager.getSimOperatorName.implementation = function () {
            return "Vodafone";
        };
        TelephonyManager.getNetworkCountryIso.implementation = function () {
            return "in";
        };
        TelephonyManager.getSimCountryIso.implementation = function () {
            return "in";
        };
        console.log("[+] Patched TelephonyManager checks");
    } catch (err) {}

    var File = Java.use("java.io.File");
    File.exists.implementation = function () {
        var name = this.getAbsolutePath();
        if (name.indexOf("goldfish") !== -1 ||
            name.indexOf("ranchu") !== -1 ||
            name.indexOf("qemu") !== -1) {
            return false;
        }
        return this.exists();
    };

    console.log("[*] Emulator detection bypass applied");
});