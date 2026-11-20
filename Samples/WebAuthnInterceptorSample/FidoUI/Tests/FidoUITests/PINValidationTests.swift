import Foundation
import Testing

@testable import FidoUI

@Suite("FIDO PIN validation")
struct PINValidationTests {
    @Test("Minimum length counts normalized Unicode code points, not graphemes")
    func countsUnicodeCodePoints() {
        let family = "👨‍👩‍👧‍👦"
        #expect(pinValidationIssue(family, minimumCodePoints: 4) == nil)
    }

    @Test("NFC normalization is used for length validation and confirmation")
    func normalizesBeforeValidationAndComparison() {
        let decomposed = String(repeating: "e\u{301}", count: 4)
        let composed = String(repeating: "é", count: 4)

        #expect(pinValidationIssue(decomposed, minimumCodePoints: 4) == nil)
        #expect(
            pinValidationIssue(decomposed, minimumCodePoints: 5)
                == .tooShort(minimumCodePoints: 5)
        )
        #expect(
            pinPairValidationIssue(
                newPIN: composed,
                repeatPIN: decomposed,
                minimumCodePoints: 4
            ) == nil
        )
    }

    @Test("UTF-8 limit accepts 63 bytes and rejects 64")
    func enforcesUTF8ByteLimit() {
        #expect(pinValidationIssue(String(repeating: "a", count: 63), minimumCodePoints: 4) == nil)
        #expect(
            pinValidationIssue(String(repeating: "a", count: 64), minimumCodePoints: 4)
                == .tooLong
        )
        #expect(
            pinValidationIssue(String(repeating: "é", count: 31) + "a", minimumCodePoints: 4)
                == nil
        )
        #expect(
            pinValidationIssue(String(repeating: "é", count: 32), minimumCodePoints: 4)
                == .tooLong
        )
    }

    @Test("Maximum byte count is checked after NFC normalization")
    func normalizesBeforeCheckingByteLimit() {
        let normalizedTo63OrFewerBytes = String(repeating: "e\u{301}", count: 31)
        let decomposed = String(repeating: "e\u{301}", count: 32)

        #expect(pinValidationIssue(normalizedTo63OrFewerBytes, minimumCodePoints: 4) == nil)
        #expect(
            pinValidationIssue(decomposed, minimumCodePoints: 4)
                == .tooLong
        )
    }
}
