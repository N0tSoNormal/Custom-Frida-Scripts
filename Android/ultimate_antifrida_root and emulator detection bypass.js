// Combined Anti-Frida + Emulator detection + Root bypass
// Includes Java hooks + native libc hooks


'use strict';

function log() {
    try { console.log.apply(console, arguments); } catch (e) {}
}
function safe(fn) { try { fn(); } catch (e) { log('[!] safe error', e); } }


if (Java.available) {
    Java.perform(function () {
        log('[*] N0tSoNormal Custom Anti-Frida, root and emulator detection bypass');


        safe(function () {
            try {
                var ClassLoader = Java.use('java.lang.ClassLoader');
                ClassLoader.loadClass.overload('java.lang.String').implementation = function (name) {
                    try {
                        if (name && name.toLowerCase().indexOf('frida') !== -1) {
                            log('[Java AntiFrida] class load blocked:', name);
                            try {
                                var k = Java.use(name);
                                // Hook boolean methods to return false, others return null
                                var methods = k.class.getDeclaredMethods();
                                methods.forEach(function (m) {
                                    var mName = m.getName();
                                    try {
                                        k[mName].overloads.forEach(function (ov) {
                                            ov.implementation = function () {
                                                log('[Java AntiFrida] ' + name + '.' + mName + '() -> bypassed');
                                                try {
                                                    var rt = ov.returnType;
                                                    if (rt && rt.class && rt.class.getName().toLowerCase().indexOf('boolean') !== -1) return false;
                                                } catch (e) {}
                                                return null;
                                            };
                                        });
                                    } catch (e) {}
                                });
                            } catch (e) {}
                        }
                    } catch (e) {}
                    return this.loadClass(name);
                };
                log('[+] Hooked ClassLoader.loadClass');
            } catch (e) { log('[!] ClassLoader hook failed', e); }
        });

 
        safe(function () {
            var RootPackages = [
                "com.noshufou.android.su","eu.chainfire.supersu","com.koushikdutta.superuser",
                "com.thirdparty.superuser","com.topjohnwu.magisk","com.devadvance.rootcloak",
                "de.robv.android.xposed.installer","com.saurik.substrate","me.phh.superuser",
                "com.dimonvideo.luckypatcher","com.chelpus.lackypatch"
            ];
            try {
                var ApplicationPackageManager = Java.use('android.app.ApplicationPackageManager');
                ApplicationPackageManager.getPackageInfo.overload('java.lang.String','int').implementation = function(pname, flags) {
                    try {
                        if (RootPackages.indexOf(pname) !== -1) {
                            log('[Root Bypass] getPackageInfo called for', pname, '-> faking');
                            // return a benign package name so check fails
                            pname = "not.exist.pkg." + Math.floor(Math.random()*10000);
                        }
                    } catch (e) {}
                    return this.getPackageInfo.overload('java.lang.String','int').call(this, pname, flags);
                };
                log('[+] Hooked ApplicationPackageManager.getPackageInfo');
            } catch (e) { log('[!] PackageManager.getPackageInfo hook failed', e); }
        });

        safe(function () {
            try {
                var File = Java.use('java.io.File');
                var suspiciousFiles = [
                    '/system/xbin/su','/system/bin/su','/system/app/Superuser.apk','/sbin/su',
                    '/vendor/bin/su','/system/bin/.ext/.su','/system/xbin/daemonsu','/data/local/xbin/su',
                    '/data/local/bin/su','/data/local/tmp/magisk', 'magisk', 'su'
                ];
                File.exists.implementation = function () {
                    try {
                        var p = this.getAbsolutePath();
                        if (p) {
                            var lp = p.toLowerCase();
                            for (var i=0;i<suspiciousFiles.length;i++) {
                                if (lp.indexOf(suspiciousFiles[i]) !== -1 || lp.indexOf('magisk') !== -1 || lp.indexOf('su') !== -1 && lp.endsWith('/su')) {
                                    log('[Root Bypass] hiding file.exists for', p);
                                    return false;
                                }
                            }
                        }
                    } catch (e) {}
                    return this.exists.call(this);
                };
                log('[+] Hooked java.io.File.exists');
            } catch (e) { log('[!] File.exists hook failed', e); }
        });


        safe(function () {
            try {
                var SystemProperties = Java.use('android.os.SystemProperties');
                var rootProps = {
                    'ro.build.tags': 'release-keys',
                    'ro.debuggable': '0',
                    'service.adb.root': '0',
                    'ro.secure': '1'
                };
                SystemProperties.get.overload('java.lang.String').implementation = function(k) {
                    try {
                        if (k && rootProps.hasOwnProperty(k)) {
                            log('[Root Bypass] SystemProperties.get(' + k + ') -> ' + rootProps[k]);
                            return rootProps[k];
                        }
                    } catch (e) {}
                    return this.get.call(this, k);
                };
                log('[+] Hooked SystemProperties.get');
            } catch (e) { log('[!] SystemProperties hook failed (may be hidden API)', e); }
        });


        safe(function () {
            try {
                var Build = Java.use('android.os.Build');
                var fake = {
                    BRAND: 'Google',
                    DEVICE: 'sailfish',
                    MODEL: 'Pixel 2',
                    PRODUCT: 'sailfish',
                    MANUFACTURER: 'Google',
                    HARDWARE: 'sailfish',
                    HOST: 'android-build',
                    FINGERPRINT: 'google/sailfish/sailfish:9/PPP1.180202.123/1234567:user/release-keys',
                };
                try { Build.BRAND.value = fake.BRAND; } catch (e) {}
                try { Build.DEVICE.value = fake.DEVICE; } catch (e) {}
                try { Build.MODEL.value = fake.MODEL; } catch (e) {}
                try { Build.PRODUCT.value = fake.PRODUCT; } catch (e) {}
                try { Build.MANUFACTURER.value = fake.MANUFACTURER; } catch (e) {}
                try { Build.HARDWARE.value = fake.HARDWARE; } catch (e) {}
                try { Build.HOST.value = fake.HOST; } catch (e) {}
                try { Build.FINGERPRINT.value = fake.FINGERPRINT; } catch (e) {}
                log('[+] Spoofed android.os.Build fields');
            } catch (e) { log('[!] Build spoof failed', e); }
        });

        safe(function () {
            try {
                var SettingsSecure = Java.use('android.provider.Settings$Secure');
                SettingsSecure.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (resolver, name) {
                    try {
                        if (name && name.toString() === SettingsSecure.ANDROID_ID.value) {
                            log('[Emu Bypass] Settings.Secure.ANDROID_ID -> fake');
                            return 'a1b2c3d4e5f6g7h8';
                        }
                    } catch (e) {}
                    return this.getString(resolver, name);
                };
                log('[+] Hooked Settings.Secure.getString for ANDROID_ID');
            } catch (e) { log('[!] Settings.Secure hook failed', e); }
        });

        safe(function () {
            try {
                var TM = Java.use('android.telephony.TelephonyManager');
                // getDeviceId() -> no args
                try {
                    TM.getDeviceId.overload().implementation = function () {
                        log('[Emu Bypass] TelephonyManager.getDeviceId() -> fake IMEI');
                        return '351565123456789';
                    };
                } catch (e) {}
               
                try {
                    TM.getDeviceId.overload('int').implementation = function (slot) {
                        log('[Emu Bypass] TelephonyManager.getDeviceId(int) -> fake IMEI slot', slot);
                        return '351565987654321';
                    };
                } catch (e) {}
              
                try { TM.getSimSerialNumber.overload().implementation = function () { log('[Emu Bypass] getSimSerialNumber'); return '8991101200003204512'; }; } catch (e) {}
                try { TM.getSubscriberId.overload().implementation = function () { log('[Emu Bypass] getSubscriberId'); return '310260000000000'; }; } catch (e) {}
                try { TM.getLine1Number.overload().implementation = function () { log('[Emu Bypass] getLine1Number'); return '+15550123456'; }; } catch (e) {}
                try { TM.getNetworkOperatorName.overload().implementation = function () { return 'Vodafone'; }; } catch (e) {}
                log('[+] TelephonyManager hooks installed (overloads safe)');
            } catch (e) { log('[!] TelephonyManager hooks failed', e); }
        });


        safe(function () {
            try {
                var SensorManager = Java.use('android.hardware.SensorManager');
                SensorManager.getSensorList.overload('int').implementation = function (type) {
                    try {
                        var list = this.getSensorList(type);
                        if (list && list.size && list.size() === 0) {
                            log('[Emu Bypass] empty sensor list -> try to return all sensors');
                            try {
                                var all = this.getSensorList(-1);
                                if (all && all.size && all.size() > 0) return all;
                            } catch (e) {}
                        }
                    } catch (e) {}
                    return this.getSensorList(type);
                };
                log('[+] SensorManager.getSensorList hooked');
            } catch (e) { log('[!] SensorManager hook failed', e); }
        });

   
        safe(function () {
            try {
                var PM = Java.use('android.content.pm.PackageManager');
                PM.hasSystemFeature.overload('java.lang.String').implementation = function (feat) {
                    try {
                        var s = feat ? feat.toString().toLowerCase() : '';
                        var allow = ['telephony', 'camera', 'location', 'accelerometer', 'camera.autofocus'];
                        for (var i=0;i<allow.length;i++) if (s.indexOf(allow[i]) !== -1) { log('[Emu Bypass] hasSystemFeature ' + feat + ' -> true'); return true; }
                    } catch (e) {}
                    return this.hasSystemFeature(feat);
                };
                log('[+] PackageManager.hasSystemFeature hooked');
            } catch (e) { log('[!] PackageManager.hasSystemFeature hook failed', e); }
        });


        safe(function () {
            try {
                var Runtime = Java.use('java.lang.Runtime');
                // many overloads — choose common ones explicitly
                try {
                    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
                        try {
                            var s = cmd ? cmd.toString() : '';
                            if (s.indexOf('getprop') !== -1 || s.indexOf('mount') !== -1 || s.indexOf('build.prop') !== -1 || s === 'su' || s.indexOf('which su') !== -1) {
                                log('[Root Bypass] Runtime.exec blocked:', s);
                                // return a harmless fallback
                                return this.exec('grep');
                            }
                        } catch (e) {}
                        return this.exec(cmd);
                    };
                } catch (e) {}
                try {
                    Runtime.exec.overload('[Ljava.lang.String;').implementation = function (arr) {
                        try {
                            for (var i=0;i<arr.length;i++) {
                                var t = arr[i] ? arr[i].toString() : '';
                                if (t.indexOf('getprop') !== -1 || t === 'su' || t.indexOf('mount') !== -1) {
                                    log('[Root Bypass] Runtime.exec(arr) blocked:', arr);
                                    return this.exec('grep');
                                }
                            }
                        } catch (e) {}
                        return this.exec(arr);
                    };
                } catch (e) {}
                log('[+] Runtime.exec hooks installed');
            } catch (e) { log('[!] Runtime.exec hook failed', e); }
        });

        safe(function () {
            try {
                var PB = Java.use('java.lang.ProcessBuilder');
                PB.start.implementation = function () {
                    try {
                        var cmd = this.command ? this.command() : null;
                        if (cmd) {
                            for (var i=0;i<cmd.size();i++) {
                                var t = cmd.get(i).toString();
                                if (t.indexOf('getprop') !== -1 || t === 'su' || t.indexOf('mount') !== -1) {
                                    log('[Root Bypass] ProcessBuilder.start blocked:', cmd);
                                    this.command.call(this, Java.array('java.lang.String', ['grep']));
                                    break;
                                }
                            }
                        }
                    } catch (e) {}
                    return this.start.call(this);
                };
                log('[+] ProcessBuilder.start hooked');
            } catch (e) { log('[!] ProcessBuilder hook failed', e); }
        });


        safe(function () {
            try {
                var BR = Java.use('java.io.BufferedReader');
                BR.readLine.overload('boolean').implementation = function (ignore) {
                    try {
                        var text = this.readLine.overload('boolean').call(this, ignore);
                        if (text && text.indexOf && text.indexOf('ro.build.tags=test-keys') !== -1) {
                            log('[Root Bypass] changing ro.build.tags to release-keys');
                            text = text.replace('ro.build.tags=test-keys', 'ro.build.tags=release-keys');
                        }
                        return text;
                    } catch (e) {}
                    return this.readLine.overload('boolean').call(this, ignore);
                };
                log('[+] BufferedReader.readLine hook installed (build.prop tweak)');
            } catch (e) { log('[!] BufferedReader hook failed', e); }
        });

        
        safe(function () {
            try {
                var JString = Java.use('java.lang.String');
                JString.contains.overload('java.lang.CharSequence').implementation = function (cs) {
                    try {
                        var s = cs ? cs.toString() : '';
                        if (s === 'test-keys') {
                            log('[Root Bypass] String.contains called for test-keys -> false');
                            return false;
                        }
                    } catch (e) {}
                    return this.contains(cs);
                };
                log('[+] String.contains hooked for test-keys');
            } catch (e) { log('[!] String.contains hook failed', e); }
        });

       
        safe(function () {
            try {
                Java.enumerateLoadedClasses({
                    onMatch: function (name) {
                        try {
                            var lname = name.toLowerCase();
                            if (lname.indexOf('emulator') !== -1 || lname.indexOf('emul') !== -1 || lname.indexOf('detect') !== -1) {
                                try {
                                    var K = Java.use(name);
                                    if (K && K.isEmulator) {
                                        try {
                                            K.isEmulator.implementation = function () { log('[Emu Bypass] ' + name + '.isEmulator() -> false'); return false; };
                                        } catch (e) {}
                                    }
                                } catch (e) {}
                            }
                        } catch (e) {}
                    },
                    onComplete: function () {}
                });
                log('[+] scanned loaded classes for isEmulator hooks');
            } catch (e) { log('[!] class enumerate failed', e); }
        });

        log('[*] merged_bypass: Java.perform end');
    }); // Java.perform
} else {
    log('[-] Java not available');
}

safe(function () {
    try {
        log('[*] merged_bypass: Installing native hooks (libc)');

        // helper list
        var nativeTargets = ['open', 'openat', 'access', 'readlink', 'stat', 'stat64', 'fopen', 'ptrace', 'system'];
        nativeTargets.forEach(function (name) {
            try {
                var addr = Module.findExportByName('libc.so', name) || Module.findExportByName(null, name);
                if (!addr) {
                    // try alternate libc names
                    addr = Module.findExportByName('libc.so.6', name);
                }
                if (addr) {
                    Interceptor.attach(addr, {
                        onEnter: function (args) {
                            try {
                                // first argument is usually char *path or int request
                                var p = null;
                                try { p = Memory.readUtf8String(args[0]); } catch (e) {}
                                if (p) {
                                    var lp = p.toLowerCase();
                                    // hide common frida/magisk/su/proc indicators
                                    var blockPatterns = ['frida', '/proc/self/maps', 'magisk', '/system/bin/su', '/system/xbin/su', 'su '];
                                    for (var i=0;i<blockPatterns.length;i++) {
                                        if (lp.indexOf(blockPatterns[i]) !== -1 || lp.endsWith('/su')) {
                                            log('[Native Bypass] ' + name + '("' + p + '") -> faking not-found');
                                            this._fake = true;
                                            break;
                                        }
                                    }
                                }
                                // special: ptrace -> neutralize
                                if (name === 'ptrace') {
                                    log('[Native Bypass] ptrace intercepted -> neutralized');
                                    try { args[0] = ptr(0); } catch (e) {}
                                }
                            } catch (e) {}
                        },
                        onLeave: function (retval) {
                            try {
                                if (this._fake) {
                                    // many syscalls return -1 on failure; return -1 here
                                    retval.replace(ptr(-1));
                                }
                            } catch (e) {}
                        }
                    });
                    log('[+] Attached native hook for', name, '->', addr);
                } else {
                    // log not noisy
                }
            } catch (e) {}
        });

        // Interceptor for fopen specifically to change requested path to /notexists when suspicious
        try {
            var fopenPtr = Module.findExportByName('libc.so', 'fopen') || Module.findExportByName(null, 'fopen');
            if (fopenPtr) {
                Interceptor.attach(fopenPtr, {
                    onEnter: function (args) {
                        try {
                            var path = Memory.readUtf8String(args[0]);
                            if (path && (path.toLowerCase().indexOf('su') !== -1 || path.toLowerCase().indexOf('magisk') !== -1 || path.toLowerCase().indexOf('frida') !== -1)) {
                                log('[Native Bypass] fopen("' + path + '") -> redirect to /notexist');
                                Memory.writeUtf8String(args[0], '/notexist');
                                this._fake = true;
                            }
                        } catch (e) {}
                    },
                    onLeave: function (ret) {}
                });
                log('[+] fopen interceptor installed');
            }
        } catch (e) {}

        // Interceptor for system() to rewrite getprop/su/mount calls
        try {
            var systemPtr = Module.findExportByName('libc.so', 'system') || Module.findExportByName(null, 'system');
            if (systemPtr) {
                Interceptor.attach(systemPtr, {
                    onEnter: function (args) {
                        try {
                            var cmd = Memory.readUtf8String(args[0]);
                            if (cmd && (cmd.indexOf('getprop') !== -1 || cmd.indexOf('mount') !== -1 || cmd === 'su' || cmd.indexOf('build.prop') !== -1)) {
                                log('[Native Bypass] system("' + cmd + '") -> rewrite to grep');
                                Memory.writeUtf8String(args[0], 'grep');
                            }
                        } catch (e) {}
                    },
                    onLeave: function (ret) {}
                });
                log('[+] system() interceptor installed');
            }
        } catch (e) {}

        log('[*] merged_bypass: native hooks installed');
    } catch (e) { log('[!] native hooks install failed', e); }
});

log('[*] merged_bypass.js loaded');
