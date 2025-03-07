# Android Mobile Application Testing Guide

## ANDROID MOBILE APPLICATION TESTING

### Tools Required

#### 1. Mobile Security Framework (MobSF) for Android Testing
- Download and install:
  - [Mobile-Security-Framework-MobSF-master](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
  - [Win64 OpenSSL](https://slproweb.com/products/Win32OpenSSL.html)
  - [Git-2.32.0-64-bit](https://git-scm.com/download/win)
  - [wkhtmltopdf](https://wkhtmltopdf.org/downloads.html)
  - [Python 3.7.0](https://www.python.org/downloads/release/python-370/)
  - [Visual Studio](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Community&rel=16)
  - [Open JDK 16](https://adoptopenjdk.net/?variant=openjdk16&jvmVariant=hotspot)

- Place `wkhtmltopdf` inside the `Mobile-Security-Framework-MobSF-master` folder and unzip it.

- Open CMD and navigate to the MobSF directory, then execute:
```sh
C:\Users\(username)\Downloads\Mobile-Security-Framework-MobSF-master>setup.bat
C:\Users\(username)\Downloads\Mobile-Security-Framework-MobSF-master>run.bat
```
- Once the application starts, open a browser and visit:
  `http://127.0.0.1:8000/`
- Drag and drop the APK file into the browser for analysis.

#### 2. Frida & Objection
- Open CMD and navigate to the Python scripts directory:
```sh
cd C:\Users\shank\AppData\Local\Programs\Python\Python39\Scripts
pip install frida
pip install frida-tools
pip install objection
```
- Update Frida:
```sh
pip install --upgrade frida-tools
```

**Test 1 - No Root Detection**
- Open ADB shell:
```sh
adb shell
#ps -A | grep (package name)
#id
```

#### 3. Platform Tools
- Download and unzip: [ADB and Fastboot SDK Platform Tools](https://rootmygalaxy.net/download-latest-adb-and-fastboot-sdk-platform-tools/)

#### 4. Genymotion - Android Emulator for App Testing
- Download: [Genymotion](https://www.genymotion.com/download/)

#### 5. Virtual Machine (VM Box)
- Download: [Oracle VirtualBox](https://www.virtualbox.org/)

#### 6. JDAX (Decompiler)
- Download: [JDAX](https://github.com/skylot/jadx/releases)

#### 7. Download APK from Play Store
- Copy the application URL from the Play Store and paste it into: [APKPure](https://apkpure.com/)
- Download the APK.

#### 8. Pull Local Storage Data
- Use ADB to pull data:
```sh
adb pull data/data/(package name)
```
- If unsuccessful, move files individually:
```sh
adb shell
cd data/data
ls  # Find application package
cd (package name)
ls  # List files
adb pull data/data/(package name)/(file name)
```
- Open the `databases` folder and use an SQL DB browser to check for sensitive data.

#### 9. Signature Verification
- Install `apksigner` in Kali Linux:
```sh
apt-get install apksigner
```
- Place the APK in the home directory and verify:
```sh
apksigner verify -v (apk_name.apk)
jarsigner -verify -verbose -certs my_application.apk
```

#### 10. Task Hijacking
- Decompile APK using apktool:
```sh
apktool d com.example.app
cd com.example.app
grep -r singleTask
```
- Reference: [Android Task Hijacking](https://github.com/smhuda/android-task-hijacking)

#### 11. APK Decompilation
- Download APK Tool and copy the APK file inside the APK Tool folder.
- Open CMD in that location and run:
```sh
java -jar apktool.jar d (apk-name.apk)
```
- Open the decompiled folder and check `AndroidManifest.xml` and `res/values/strings.xml` for sensitive information.

#### 12. Exported Activity Testing
```sh
adb shell am start -n package_name/activity_name
```

#### 13. Real-time Mobile Screen Mirroring in Linux
- Use `scrcpy` for real-time mirroring.

---

## Android Mobile Application Security Test Cases

| #  | Test Case                                      | Severity  | OWASP Category                      | Steps to Reproduce | Description | Status (✔/❌) |
|----|-----------------------------------------------|----------|---------------------------------|------------------|-------------|---------------|
| 1  | Hardcoded Secrets in Code                    | High     | M1: Improper Credential Storage | Decompile APK, search for API keys, credentials in `strings.xml` | Exposes API keys, credentials | ❌ |
| 2  | No Root Detection                            | High     | M9: Reverse Engineering        | Use Frida to bypass root detection | App should block execution on rooted devices | ❌ |
| 3  | Certificate Pinning Bypass                   | High     | M3: Insecure Communication     | Use Frida to intercept HTTPS traffic | Lack of pinning allows MITM attacks | ❌ |
| 4  | Sensitive Data in Logs                       | High     | M2: Insecure Data Storage      | Run `adb logcat`, check for sensitive data | Data exposure in system logs | ❌ |
| 5  | No Authentication After Background Resume    | High     | M5: Insufficient Cryptography  | Move app to background and return | App should require authentication | ❌ |
| 6  | Traffic Analysis - Weak TLS & Ciphers        | High     | M3: Insecure Communication     | Use MITM proxy to inspect TLS version | Weak TLS versions can be exploited | ❌ |
| 7  | Insecure Storage Analysis                    | High     | M2: Insecure Data Storage      | Check SQLite DB for sensitive data | Data stored unencrypted | ❌ |
| 8  | Reverse Engineering - Memory Leak           | High     | M9: Reverse Engineering        | Use memory dump analysis tools | Sensitive data may remain in memory | ❌ |
| 9  | URL Redirection via Deep Links               | Medium   | M7: Client Code Quality        | Test deep links with manipulated URLs | Can lead to phishing attacks | ❌ |
| 10 | Account Takeover via Deep Links              | Medium   | M7: Client Code Quality        | Modify deep link URLs to access unauthorized accounts | Allows unauthorized access | ❌ |
| 11 | Tapjacking Vulnerability                     | Medium   | M8: Code Tampering             | Overlay transparent UI elements | Attacker can hijack interactions | ❌ |
| 12 | Lack of Binary Obfuscation                   | Medium   | M9: Reverse Engineering        | Check for ProGuard usage | Unobfuscated apps are easy to reverse-engineer | ❌ |
| 13 | WebView Injection                            | Medium   | M7: Client Code Quality        | Inject JavaScript into WebView | Can execute arbitrary JavaScript | ❌ |
| 14 | WebViews - JavaScript Enabled                | Medium   | M7: Client Code Quality        | Test `loadUrl()` function in WebView | JavaScript can be exploited | ❌ |
| 15 | Application Declares Max SDK Version         | Low      | M7: Client Code Quality        | Check `maxSdkVersion` in manifest | Limits compatibility and security updates | ❌ |
| 16 | Allow Backup Enabled                         | Low      | M2: Insecure Data Storage      | Check `android:allowBackup="true"` in manifest | Allows backup extraction of app data | ❌ |
| 17 | Cleartext Traffic Allowed                    | Low      | M3: Insecure Communication     | Check `usesCleartextTraffic="true"` in manifest | Allows unencrypted traffic | ❌ |
| 18 | Internal IP Disclosure                       | Low      | M7: Client Code Quality        | Inspect network logs for internal IPs | Exposes internal network infrastructure | ❌ |


---

## **Test Execution Guide**
1. **Setup Environment**: Install all required tools and dependencies.
2. **Load APK into MobSF**: Perform static and dynamic analysis.
3. **Test for Root Detection**: Use ADB to check app behavior on a rooted device.
4. **Decompile APK**: Analyze manifest files and sensitive data storage.
5. **Check for Task Hijacking**: Identify security vulnerabilities in exported activities.
6. **Signature Verification**: Validate app signatures using `apksigner`.
7. **Data Storage Review**: Use ADB to pull local storage data and analyze database files.
8. **Perform Dynamic Analysis**: Use Frida and Objection for runtime security checks.
9. **Screen Mirroring**: Use `scrcpy` for real-time interaction.
10. **Document Findings**: Store results in a structured format for reporting.

---

### **Download Checklist**
The full security checklist is available for download in Excel format. 

**[Download Checklist (Excel)]()**  *(Link to be added)*

---

This guide serves as a comprehensive reference for setting up an Android security testing environment and executing security test cases effectively. It is also optimized for direct use in GitHub repositories.

