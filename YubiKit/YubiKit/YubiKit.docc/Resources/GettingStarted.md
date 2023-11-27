# Getting Started

Prepare your project to connect to the YubiKey via NFC, SmartCard and Lightning.

## Overview

The YubiKit framework is distributed using the Swift Package Manager. To add the framework to your project follow these steps:

1. Select your project.

2. Choose the "Package Dependencies" tab.

3. Press the plus-button to bring up the add package dialog.

![An image showing how to add the YubiKit SDK to your Xcode project.](add-framework-1.png)

4. Enter `yubikit-swift` in the search field and select the Yubico Swift Package.

5. Press the "Add Package" button to add the SDK to your project.

![An image showing how to add the YubiKit SDK to your Xcode project.](add-framework-2.png)


### NFC

If you want your app to communicate with YubiKeys via NFC you need to add the wireless entitlement, list of NFC
application identifiers and a NFC Privacy statement to the application.

**Add Wireless entitlement**

1. Select your project.

2. Selet your application target.

3. Choose the "Signing & Capabilities" tab.

4. Click the "+"-button to add a new capability.

5. Select the "Near Field Communication Tag" capability.

![An image showing how to add wireless entitlements to project.](nfc-entitlement.png)

**Add list of NFC application identifiers**

6. Choose the "Info" tab.

7. Add the "ISO7816 application identifiers for NFC" key to the "Custom iOS Target Properties".

![An image showing how to add the nfc application identifiers.](nfc-identifiers.png)

8. Add the Yubico NFC application identifiers to enable comunication with the different
applications on the YubiKey.

```
A000000527471117  // YubiKey Management Application
A0000006472F0001  // FIDO/U2F
A0000005272101    // OATH
A000000308        // PIV
A000000527200101  // YubiKey application/OTP (for HMAC SHA1 challenge-response)
```

![An image showing the list of nfc identifiers added.](nfc-identifiers-list.png)

**Add a NFC Privacy description**

9. Add the "Privacy - NFC Usage Scan Description" key and a string that describes what you will use NFC for in
the application e.g "The application needs access to NFC reading to communicate with your YubiKey."

![An image showing how to add NFC privacy string tro project.](nfc-privacy.png)

### SmartCard/USB-C

To support YubiKeys connected via the USB-C port on a device running iOS 16 or higher, you need to add the 
`com.apple.security.smartcard` entitlement to your application.

1. Select the application entitlements file.

2. Add the `com.apple.security.smartcard` entitlement to the entitlement list.

![An image showing how to add NFC privacy string tro project.](smart-card.png)

> Note: The SmartCard/USB-C connection only support the CCID based applications on the YubiKey and does not support U2F, FIDO2 or OTP.

### Lightning/AccessoryConnection i.e 5Ci YubiKey

To add support for the 5Ci YubiKey that connect to the iPhone via the Lightning port you need to add the `com.yubico.ylp` string to the list of External Accssories.

1. Select your project.

2. Select your application target.

3. Choose the "Info" tab.

4. If not present add the `Supported external accessory protocols` key and insert the string `com.yubico.ylp` in its list.

![An image showing how to support for lightning Yubikeys.](external-accessory.png)

> Note: The YubiKey 5Ci is an Apple MFi certified external accessory and communicates over iAP2. Setting the value for `Supported external accessory protocols` to `com.yubico.ylp` will tell the app that all communication with the 5Ci YubiKey via the Lightning port is done using the External Accessory framework.

### Build SDK documentation

As a final step build the documentation for the SDK by selecting "Product" -> "Build Documention" in Xcode. This will give you
access to the YubiKit Framework documentation from the Developer Documentation window in Xcode.

> Note: Make sure to select an iOS target when building the documentation. If you build it with macOS as the target destination LightningConnection and NFCConnection will not be included in the documentation.
