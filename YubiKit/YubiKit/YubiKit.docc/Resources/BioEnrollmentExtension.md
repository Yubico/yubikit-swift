# ``YubiKit/CTAP2/BioEnrollment``

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
