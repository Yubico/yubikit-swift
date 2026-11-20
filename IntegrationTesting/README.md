# Integration testing

`IntegrationTests` runs the shared scenario catalog. The release SDK uses the
platform drivers. TwinKit runs build the same target against a dynamic YubiKit
and substitute the TwinKit framework when launching the tests.

Run scenarios from the repository root. Use `SCENARIO` to select scenarios by ID.

```bash
SCENARIO=Connection.SmartCard.open ./run-scenarios.sh twinkit
SCENARIO=Connection.SmartCard.open ./IntegrationTesting/Simulated/run-sdk.sh scenarios --simulator-id <UUID>
YUBIKEY_TEST_SERIALS=<serial> ./run-scenarios.sh hardware
```

Hardware scenarios require an explicit test key serial because some scenarios
reset applications and overwrite key data. `swift test --package-path IntegrationTesting`
runs the hardware-free checks by default.

Use `YUBIKIT_TWINKIT_TRANSPORT=nfc` for a contactless Mac TwinKit run. Set
`YUBIKIT_TWIN_PATH` to build from a local `hardware-digital-twin` checkout.

For interactive runs, see [Run samples with TwinKit](Simulated/README.md).
