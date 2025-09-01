// iOS Jailbreak Detection Bypass
var suspiciousPaths = [
    "/Applications/Cydia.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/bin/bash",
    "/usr/sbin/sshd",
    "/etc/apt"
];

var fopen = Module.findExportByName(null, "fopen");
if (fopen) {
    Interceptor.attach(fopen, {
        onEnter: function(args) {
            var path = args[0].readUtf8String();
            if (suspiciousPaths.indexOf(path) >= 0) {
                console.log("[!] Blocking fopen on " + path);
                this.shouldBlock = true;
            }
        },
        onLeave: function(retval) {
            if (this.shouldBlock) {
                retval.replace(ptr("0x0"));
            }
        }
    });
}

var sysctl = Module.findExportByName(null, "sysctl");
if (sysctl) {
    Interceptor.replace(sysctl, new NativeCallback(function() {
        console.log("[*] sysctl call spoofed");
        return 0;
    }, 'int', ['pointer','uint','pointer','pointer','pointer','size_t']));
}