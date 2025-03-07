# Android Mobile Application Testing Guide

### Setup your test machine and Mobile device/emulatro:

#### 1. Install Mobile Security Framework (MobSF) for Android Testing
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
- Open CMD and navigate to the Python scripts directory :
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
#### 2.2 Push frida to device
- Open platform tools folder CMD and push frida server file to device
```sh
C:\platform-tools>adb push C:\platform-tools\frida-server-15.1.4-android-x86_64 data/local/tmp
Next- adb shell    —   su   —-- 	cd data/local/tmp	
Download frid server-  https//github.com/frida/frida/releases
chmod +x frida-server-15.1.4-android-x86_64
./ frida-server-15.1.4-android-x86_64 (frida server should start)
```
#### 3. Platform Tools
- Download and unzip: [ADB and Fastboot SDK Platform Tools](https://rootmygalaxy.net/download-latest-adb-and-fastboot-sdk-platform-tools/)

#### 4. Emulator- 1. Genymotion - Android Emulator for App Testing
- Download: [Genymotion](https://www.genymotion.com/download/)
  
#### 4.4. Emulator- 2. Android studio
- Download: [Android studio](https://developer.android.com/studio)
- For setup Watch:  [Android studio Setup](https://www.youtube.com/watch?v=3jZw8pIO-gw)
  
#### 5. Virtual Machine (VM Box)
- Download: [Oracle VirtualBox](https://www.virtualbox.org/)

#### 6. JDAX (Decompiler)
- Download: [JDAX](https://github.com/skylot/jadx/releases)

#### 7. Download Target APK and push to the device
-Connect your device: Ensure your mobile device is connected to your computer via USB and USB debugging is enabled.
- Open a terminal or command prompt: Navigate to the directory where your APK file is located.
- Use the adb push command: Run the following command:
```sh
adb push your-app.apk /sdcard/
```
- 
**Test 1 - No Root Detection**
- Open ADB shell:
```sh
adb shell
#ps -A | grep (package name)
#id
```
Run Frida in the mobile, open Frida in CMD and use this command 
open the app in mobile before using this command
```sh
Frida-ps -Ua 
Find the package ID and package name in the list. Then
Option 1- use command {frida --codeshare dzonerzy/fridantiroot -f package_name -U} hit ENTER
                    	{%resume} it should bypass the jailbreak detection
Or
Option 2- use command {objection -g (package ID) explore} hit Enter
```
**Test 2 - SSL Pinning Bypass**
Connect mobile to PC, go to frida location open CMD.
Use command {frida-ps -Ua}
Then {objection -g (package ID) explore} and {iso sslpinning disable}
To check the traffic- connect both PC & Mobile in the same network.
 [Configure Burp proxy.](https://portswigger.net/burp/documentation/desktop/mobile/config-android-device)
 [Watch SetUp.](https://www.youtube.com/watch?v=obPZB2YUAbI)
Check in burp for the traffic.

#### 3. Pull Local Storage Data
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

#### 4. Signature Verification
- Install `apksigner` in Kali Linux:
```sh
apt-get install apksigner
```
- Place the APK in the home directory and verify:
```sh
apksigner verify -v (apk_name.apk)
jarsigner -verify -verbose -certs my_application.apk
```

#### 5. Task Hijacking
- Decompile APK using apktool:https://www.filehorse.com/download-apk-easy-tool/
```sh
apktool d com.example.app
cd com.example.app
grep -r singleTask
```
- Reference: [Android Task Hijacking](https://github.com/smhuda/android-task-hijacking)

#### 6. APK Decompilation
- Download APK Tool and copy the APK file inside the APK Tool folder.
- Open CMD in that location and run:
```sh
java -jar apktool.jar d (apk-name.apk)
or use apk easy tool https://www.filehorse.com/download-apk-easy-tool/
```
- Open the decompiled folder and check `AndroidManifest.xml` and `res/values/strings.xml` for sensitive information.

#### 7. Exported Activity Testing
```sh
adb shell am start -n package_name/activity_name
```

#### 8. Real-time Mobile Screen Mirroring in Linux
- Use `scrcpy` for real-time mirroring.

---

## Android Security Testing Checklist

| #  | Test Case                                      | Severity  | OWASP Category                      | Steps to Reproduce | Description | Status (✔/❌) |
|----|-----------------------------------------------|-----------|-------------------------------------|---------------------|-------------|---------------|
| 1  | Manifest File Issues                          | Medium    | TBD                                 | Inspect `AndroidManifest.xml` | Configuration flaws in the manifest can expose security risks. | ❌ |
| 2  | Allow Backup Enabled                         | Medium    | M2: Insecure Data Storage          | Check for `android:allowBackup="true"` | Enabling backup allows attackers to extract app data. | ❌ |
| 3  | Debug Mode Enabled                           | Medium    | TBD                                 | Check `android:debuggable="true"` | Debugging enabled can expose the app to attackers. | ❌ |
| 4  | Activity Exposure                            | High      | TBD                                 | Run `adb shell am start -n package/activity` | Exposed activities can be launched by other apps. | ❌ |
| 5  | Services Exposure                            | High      | TBD                                 | Run `adb shell am startservice -a com.google.firebase.INSTANCE_ID_EVENT` | Services can be started by unauthorized apps. | ❌ |
| 6  | Content Providers Exposure                   | High      | TBD                                 | Search `AndroidManifest.xml` for `providers` keyword | Exposed content providers can leak sensitive data. | ❌ |
| 7  | Sensitive Data in Unprotected Content Provider | High  | M2: Insecure Data Storage          | Try accessing provider data via `content://` URI | Sensitive data might be accessible by unauthorized apps. | ❌ |
| 8  | Content Provider SQL Injection               | High      | M1: Improper Platform Usage        | Inject SQL in content provider queries | Can lead to data leaks or unauthorized access. | ❌ |
| 9  | Content Provider Path Traversal              | High      | M1: Improper Platform Usage        | Try accessing restricted paths via content provider | Can expose internal app files. | ❌ |
| 10 | URL Redirection via Deep Links               | Medium    | M7: Client Code Quality            | Test for open redirects in deep link URLs | Can redirect users to malicious sites. | ❌ |
| 11 | Account Takeover via Deep Links              | High      | M7: Client Code Quality            | Analyze auto-login deep links | Weak deep link security can allow account takeovers. | ❌ |
| 12 | Insecure Deep Links                          | High      | M7: Client Code Quality            | Test for unprotected intent filters | Attackers can exploit deep links for privilege escalation. | ❌ |
| 13 | Tapjacking                                   | Medium    | M8: Code Tampering                 | Overlay transparent UI over the app | Can trick users into performing unintended actions. | ❌ |
| 14 | Custom Keyboard Allowed                      | High      | M2: Insecure Data Storage          | Enable custom keyboards and test data entry | Malicious keyboards can log user input. | ❌ |
| 15 | Screenshot Information Leakage               | High      | TBD                                 | Capture screenshots in sensitive screens | Sensitive data can be exposed via screenshots. | ❌ |
| 16 | White Screen Visible in Background           | High      | TBD                                 | Check `/data/system_ce/0/snapshots/` | Previous app state can be leaked. | ❌ |
| 17 | No Authentication After Background Resume    | High      | M5: Insufficient Cryptography      | Authenticate, switch apps, and resume | If authentication is bypassed, attackers can access user data. | ❌ |
| 18 | Authentication Bypass                        | High      | M6: Insecure Authorization         | Test login mechanisms for weak implementations | Can allow unauthorized access to user accounts. | ❌ |
| 19 | No Logout Implemented                        | Medium    | TBD                                 | Check if session persists after logout | Lack of proper logout can lead to session hijacking. | ❌ |
| 20 | Credential Stored in Memory                  | High      | TBD                                 | Dump memory after login | Credentials remain in memory after logout, leading to leaks. | ❌ |
| 21 | Sensitive Data Logged to System Logs        | High      | M2: Insecure Data Storage          | Run `adb logcat` and check logs | Logging sensitive data can expose it to attackers. | ❌ |
| 22 | Unencrypted Local Storage                    | High      | M2: Insecure Data Storage          | Inspect local storage files | Sensitive data should not be stored in plaintext. | ❌ |
| 23 | No Root Detection                            | High      | M9: Reverse Engineering            | Test app behavior on rooted devices | Rooted devices can bypass security controls. | ❌ |
| 24 | Certificate Pinning Bypass                   | High      | M3: Insecure Communication         | Use Burp Suite or Frida to intercept traffic | If pinning is not enforced, MITM attacks are possible. | ❌ |
| 25 | Internal IP Disclosure                       | Medium    | TBD                                 | Inspect responses and error messages | Leaking internal IPs can aid attackers in network enumeration. | ❌ |
| 26 | Lack of Binary Obfuscation                   | High      | M9: Reverse Engineering            | Decompile the APK and analyze code readability | Unobfuscated code is easier to reverse-engineer. | ❌ |
| 27 | Vulnerable Cordova/PhoneGap Version         | High      | TBD                                 | Check Cordova version (below 6.4.0 is vulnerable) | Outdated frameworks may have known vulnerabilities. | ❌ |
| 28 | PhoneGap or Cordova Access Origin Too Broad | High      | TBD                                 | Check `config.xml` for `access origin="*"` | Can allow external JavaScript execution. | ❌ |
| 29 | WebView Injection                           | High      | M7: Client Code Quality            | Inject JavaScript into WebView | Unprotected WebViews can execute malicious scripts. | ❌ |
| 30 | Sensitive Data in WebView Cache             | High      | M7: Client Code Quality            | Analyze WebView cache storage | Cached sensitive data can be extracted. | ❌ |
| 31 | Janus Vulnerability                         | High      | TBD                                 | Check if app is signed only with v1 scheme | v1-only signing is vulnerable to Janus attack. | ❌ |
| 32 | Weak Certificate Usage                      | High      | TBD                                 | Run `keytool -printcert -file CERT.RSA` | Weak certificates can be exploited by attackers. | ❌ |
| 33 | Random() Function Used                      | High      | TBD                                 | Check for `java.util.Random()` usage | Weak randomness can lead to predictable values. | ❌ |
| 34 | `addJavascriptInterface()` Exploitable      | High      | M7: Client Code Quality            | Check if `removeJavascriptInterface()` is missing | Can expose JavaScript to native execution risks. | ❌ |
| 35 | `loadUrl()` in WebView Without Validation   | High      | M7: Client Code Quality            | Check WebView `loadUrl()` calls | Unvalidated URLs can lead to XSS attacks. | ❌ |
| 36 | Application Declares a Maximum SDK Version  | Medium    | TBD                                 | Check `maxSdkVersion` in `AndroidManifest.xml` | Can block security updates if misconfigured. | ❌ |
| 37 | Outdated SSL/TLS Version Used               | High      | M3: Insecure Communication         | Inspect SSL libraries in use | Using outdated TLS versions exposes the app to vulnerabilities. | ❌ |

---

### How to Use This Checklist:
1. **Severity**: Categorized as **High**, **Medium**, or **Low** based on impact.
2. **OWASP Category**: Aligned with **OWASP Mobile Top 10** where applicable.
3. **Steps to Reproduce**: Quick methods to validate each finding.
4. **Status**: Use **✔ for Pass** and **❌ for Fail** to track issues.

> 🚀 **This checklist helps in performing structured security testing of Android applications.**




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



---

This guide serves as a comprehensive reference for setting up an Android security testing environment and executing security test cases effectively. It is also optimized for direct use in GitHub repositories.

