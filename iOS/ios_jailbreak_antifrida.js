'use strict';

if (ObjC.available) {
  const suspiciousPaths = [
    "/Applications/Cydia.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/bin/bash",
    "/usr/sbin/sshd",
    "/etc/apt",
    "/private/var/lib/apt/",
    "/private/var/stash",
    "/private/var/tmp/cydia.log",
    "/Applications/FakeCarrier.app",
    "/Applications/SBSettings.app",
    "/Applications/blackra1n.app",
    "/Applications/IntelliScreen.app",
    "/Applications/MxTube.app",
    "/Applications/RockApp.app"
  ];

  function blockFileAccess() {
    const access = Module.findExportByName(null, "access");
    if (access) {
      Interceptor.attach(access, {
        onEnter: function (args) {
          this.path = Memory.readCString(args[0]);
          if (suspiciousPaths.includes(this.path)) {
            console.log("[+] Blocked access to: " + this.path);
            this.shouldFake = true;
          }
        },
        onLeave: function (retval) {
          if (this.shouldFake) retval.replace(-1);
        }
      });
    }

    const stat = Module.findExportByName(null, "stat");
    if (stat) {
      Interceptor.attach(stat, {
        onEnter: function (args) {
          this.path = Memory.readCString(args[0]);
          if (suspiciousPaths.includes(this.path)) {
            console.log("[+] Blocked stat on: " + this.path);
            this.shouldFake = true;
          }
        },
        onLeave: function (retval) {
          if (this.shouldFake) retval.replace(-1);
        }
      });
    }
  }

  function blockDlopenFridaLibs() {
    const dlopen = Module.findExportByName(null, "dlopen");
    if (dlopen) {
      Interceptor.attach(dlopen, {
        onEnter: function (args) {
          const path = Memory.readCString(args[0]);
          if (path && path.toLowerCase().includes("frida")) {
            console.log("[!] Blocking Frida lib load: " + path);
            this.shouldBlock = true;
          }
        },
        onLeave: function (retval) {
          if (this.shouldBlock) retval.replace(ptr(0));
        }
      });
    }
  }

  function spoofSysctl() {
    const sysctl = Module.findExportByName(null, "sysctl");
    if (sysctl) {
      Interceptor.attach(sysctl, {
        onEnter: function (args) {
          const name0 = Memory.readU32(args[0]);
          const name1 = Memory.readU32(args[0].add(4));
          if ((name0 === 1 && name1 === 14) || name1 === 1) { // CTL_KERN, KERN_PROC
            console.log("[*] sysctl call spoofed");
            this.shouldSpoof = true;
          }
        },
        onLeave: function (retval) {
          if (this.shouldSpoof) retval.replace(-1);
        }
      });
    }
  }

  function blockPtrace() {
    const ptrace = Module.findExportByName(null, "ptrace");
    if (ptrace) {
      Interceptor.attach(ptrace, {
        onEnter: function (args) {
          console.log("[*] ptrace called - faking EPERM");
          this.block = true;
        },
        onLeave: function (retval) {
          if (this.block) retval.replace(-1);
        }
      });
    }
  }

  function blockFridaAgentDetection() {
    const dlsym = Module.findExportByName(null, "dlsym");
    if (dlsym) {
      Interceptor.attach(dlsym, {
        onEnter: function (args) {
          const sym = Memory.readCString(args[1]);
          if (sym.toLowerCase().includes("frida")) {
            console.log("[*] dlsym for Frida symbol: " + sym);
            this.block = true;
          }
        },
        onLeave: function (retval) {
          if (this.block) retval.replace(ptr(0));
        }
      });
    }
  }

  console.log("[*] iOS bypass script loaded.");
  blockFileAccess();
  blockDlopenFridaLibs();
  spoofSysctl();
  blockPtrace();
  blockFridaAgentDetection();
}
