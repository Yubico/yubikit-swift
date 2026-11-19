# Run samples with TwinKit

The helper builds the sample with its existing Xcode scheme and the real SDK. A
development SwiftPM manifest builds YubiKit as a dynamic framework. The helper
builds a second framework with TwinKit drivers and selects it when launching the sample.
Each framework selects its drivers at build time.

Both frameworks must come from the same SDK checkout and use the same toolchain,
dependencies, and Debug build settings. Run the build again after changing SDK
or sample sources.

Run the OATH, WebAuthn, and IntegrationTesting apps on macOS or pass
`--simulator-id` to run them on iOS Simulator. The PIV CLI runs on macOS.
Pass its command and options after `--`. Quit a macOS app to return to the shell
that launched it.

Run these commands from the repository root.

```bash
./IntegrationTesting/Simulated/run-sdk.sh run --sample oath
./IntegrationTesting/Simulated/run-sdk.sh run --sample piv -- info
./IntegrationTesting/Simulated/run-sdk.sh run --simulator-id <UUID> --sample webauthn --transport nfc
```

Xcode, `xcodebuildmcp`, and `jq` are required. For iOS, install a Simulator runtime
and use a Simulator reserved for development. The helper installs the app with its
usual bundle identifier. TwinKit requires access to its private repository and Python
release asset. To use a local checkout, pass `--twin-path` or set `YUBIKIT_TWIN_PATH`.

Use `launch` to reuse a build with a different profile or transport.

```bash
./IntegrationTesting/Simulated/run-sdk.sh launch --simulator-id <UUID> --profile 5-fips
./IntegrationTesting/Simulated/run-sdk.sh launch --sample piv --profile 5-fips -- list
```

The default transport is USB. Use `--no-nfc-reader` to simulate a host without an
NFC reader. Each launch starts a fresh virtual key. Build products and logs live
under `.build/simulated-sdk`.

For automated tests, see [Integration testing](../README.md).
