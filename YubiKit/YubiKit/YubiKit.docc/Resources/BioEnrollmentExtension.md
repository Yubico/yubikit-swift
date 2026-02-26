# ``YubiKit/CTAP2/BioEnrollment``

Fingerprint enrollment operations for biometric authenticators (e.g., YubiKey Bio).

## Overview

BioEnrollment manages fingerprint enrollments on biometric authenticators. It requires a
PIN/UV auth token with the ``CTAP2/ClientPin/Permission/bioEnrollment`` permission.

```swift
let token = try await session.getPinUVToken(
    using: .pin("123456"),
    permissions: [.bioEnrollment]
)
let bio = try await session.bioEnrollment(token: token)

// Check sensor capabilities
let sensorInfo = try await bio.getFingerprintSensorInfo()

// Enroll a new fingerprint
for try await sample in bio.enroll(timeout: 10000) {
    switch sample {
    case .waitingForUser:
        print("Touch the sensor...")
    case .sample(let status, let remaining):
        print("Captured: \(status), \(remaining) remaining")
    case .completed(let templateId, _):
        print("Enrollment complete!")
    }
}

// List existing enrollments
for try await enrollment in bio.enrollments {
    print("\(enrollment.templateId): \(enrollment.friendlyName ?? "unnamed")")
}
```

## Topics

### Feature Detection

- ``isSupported(by:)``

### Sensor Information

- ``getFingerprintSensorInfo()``

### Enrollment Operations

- ``enroll(timeout:)``
- ``cancelEnrollment()``

### Managing Enrollments

- ``enrollments``
- ``setFriendlyName(_:for:)``
- ``removeEnrollment(_:)``

### Related Types

- ``FingerprintSensorInfo``
- ``FingerprintKind``
- ``SampleStatus``
- ``TemplateInfo``
- ``EnrollmentSample``
- ``EnrollFingerprint``
- ``EnrollmentSequence``
