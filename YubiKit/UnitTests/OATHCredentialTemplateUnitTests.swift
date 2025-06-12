// Copyright Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import CommonCrypto
import Foundation
import Testing
import YubiKit

struct OATHCredentialTemplateUnitTests {

    @Test func tOTPWithURL() throws {
        let url = URL(
            string:
                "otpauth://totp/Issuer-in-path:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=Issuer-in-parameter&algorithm=SHA256&digits=8&period=30"
        )!
        do {
            let template = try OATHSession.CredentialTemplate(withURL: url)
            if case let OATHSession.CredentialType.TOTP(period) = template.type {
                #expect(period == 30)
            } else {
                Issue.record("Wrong account type")
            }
            #expect(template.algorithm == .SHA256)
            #expect(template.digits == 8)
            #expect(template.name == "john@example.com")
            #expect(template.issuer == "Issuer-in-path")
        } catch {
            Issue.record("Failed with error: \(error)")
        }
    }

    @Test func totpWithIssuerInParameterWithURL() throws {
        let url = URL(string: "otpauth://totp/john@example.com?secret=HXDM&issuer=Issuer-in-parameter")!
        do {
            let template = try OATHSession.CredentialTemplate(withURL: url)
            if case let OATHSession.CredentialType.TOTP(period) = template.type {
                #expect(period == 30)
            } else {
                Issue.record("Wrong account type")
            }
            #expect(template.algorithm == .SHA1)
            #expect(template.digits == 6)
            #expect(template.name == "john@example.com")
            #expect(template.issuer == "Issuer-in-parameter")
        } catch {
            Issue.record("Failed with error: \(error)")
        }
    }

    @Test func tOTPWithDefaultsWithURL() throws {
        let url = URL(
            string:
                "otpauth://totp/Issuer-in-path:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=Issuer-in-parameter"
        )!
        do {
            let template = try OATHSession.CredentialTemplate(withURL: url)
            if case let OATHSession.CredentialType.TOTP(period) = template.type {
                #expect(period == 30)
            } else {
                Issue.record("Wrong account type")
            }
            #expect(template.algorithm == .SHA1)
            #expect(template.digits == 6)
            #expect(template.name == "john@example.com")
            #expect(template.issuer == "Issuer-in-path")
        } catch {
            Issue.record("Failed with error: \(error)")
        }
    }

    @Test func totpSkipValidationWithURL() throws {
        let url = URL(string: "otpauth://totp/?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=Issuer-in-parameter")!
        do {
            let template = try OATHSession.CredentialTemplate(withURL: url, skipValidation: true)
            if case let OATHSession.CredentialType.TOTP(period) = template.type {
                #expect(period == 30)
            } else {
                Issue.record("Wrong account type")
            }
            #expect(template.algorithm == .SHA1)
            #expect(template.digits == 6)
            #expect(template.name == "")
            #expect(template.issuer == nil)
        } catch {
            Issue.record("Failed with error: \(error)")
        }
    }

    @Test func hotpWithURL() throws {
        let url = URL(
            string:
                "otpauth://hotp/Issuer-in-path:john@example.com?secret=HXDM&issuer=Issuer-in-parameter&algorithm=SHA256&digits=8&counter=4711"
        )!
        do {
            let template = try OATHSession.CredentialTemplate(withURL: url)
            if case let OATHSession.CredentialType.HOTP(counter) = template.type {
                #expect(counter == 4711)
            } else {
                Issue.record("Wrong account type")
            }
            #expect(template.algorithm == .SHA256)
            #expect(template.digits == 8)
            #expect(template.name == "john@example.com")
            #expect(template.issuer == "Issuer-in-path")
        } catch {
            Issue.record("Failed with error: \(error)")
        }
    }

    @Test func hotpWithDefaultsWithURL() throws {
        let url = URL(string: "otpauth://hotp/Issuer-in-path:john@example.com?secret=HXDM&issuer=Issuer-in-parameter")!
        do {
            let template = try OATHSession.CredentialTemplate(withURL: url)
            if case let OATHSession.CredentialType.HOTP(counter) = template.type {
                #expect(counter == 0)
            } else {
                Issue.record("Wrong account type")
            }
            #expect(template.algorithm == .SHA1)
            #expect(template.digits == 6)
            #expect(template.name == "john@example.com")
            #expect(template.issuer == "Issuer-in-path")
        } catch {
            Issue.record("Failed with error: \(error)")
        }
    }

    @Test func shortSecretWithURL() throws {
        let url = URL(string: "otpauth://totp/yubico?secret=HXDM")!
        do {
            let template = try OATHSession.CredentialTemplate(withURL: url)
            let expectedSecret = Data([
                0x3d, 0xc6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ])
            #expect(template.secret == expectedSecret)
        } catch {
            Issue.record("Failed with error: \(error)")
        }
    }

    @Test func longSHA1SecretWithURL() throws {
        let url = URL(
            string:
                "otpauth://totp/yubico?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZHXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZHXDMVJECJJWSRB3HWIZR4IFUGFTMXHXDMVJECJJWSHXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZHXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZHXDMVJECJJWSRB3HWIZR4IFUGFTMXHXDMVJECJJWS&algorithm=SHA1"
        )!
        do {
            let template = try OATHSession.CredentialTemplate(withURL: url)
            let expectedSecret = Data([
                0x6b, 0x2c, 0x5d, 0xa4, 0x82, 0x65, 0x43, 0x0c, 0xa8, 0x7c, 0xab, 0x40, 0x4b, 0x54, 0x12, 0x9e, 0xcf,
                0xf8, 0xed, 0x76,
            ])
            #expect(template.secret == expectedSecret)
        } catch {
            Issue.record("Failed with error: \(error)")
        }
    }

    @Test func longSHA256SecretWithURL() throws {
        let url = URL(
            string:
                "otpauth://totp/yubico?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZHXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZHXDMVJECJJWSRB3HWIZR4IFUGFTMXHXDMVJECJJWSHXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZHXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZHXDMVJECJJWSRB3HWIZR4IFUGFTMXHXDMVJECJJWS&algorithm=SHA256"
        )!
        do {
            let template = try OATHSession.CredentialTemplate(withURL: url)
            let expectedSecret = Data([
                0x0f, 0x19, 0xec, 0xcd, 0xd4, 0xc0, 0xff, 0xa2, 0x27, 0x2c, 0x96, 0x09, 0xc7, 0x3b, 0xc2, 0x24, 0x83,
                0xbd, 0xb7, 0x38, 0x88, 0xff, 0xe1, 0x35, 0x63, 0x5a, 0xd0, 0xe3, 0x16, 0x93, 0xc6, 0x51,
            ])
            #expect(template.secret == expectedSecret)
        } catch {
            Issue.record("Failed with error: \(error)")
        }
    }

    @Test func longSHA512SecretWithURL() throws {
        let url = URL(
            string:
                "otpauth://totp/yubico?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZHXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZHXDMVJECJJWSRB3HWIZR4IFUGFTMXHXDMVJECJJWSHXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZHXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZHXDMVJECJJWSRB3HWIZR4IFUGFTMXHXDMVJECJJWS&algorithm=SHA512"
        )!
        do {
            let template = try OATHSession.CredentialTemplate(withURL: url)
            let expectedSecret = Data([
                0x7f, 0x5b, 0x11, 0x56, 0x3f, 0x57, 0x8c, 0x65, 0x9a, 0xf3, 0xa0, 0x22, 0x43, 0xd5, 0x9c, 0xd0, 0x14,
                0xec, 0xec, 0x4a, 0xf8, 0x2b, 0xdb, 0x7e, 0xd6, 0x5c, 0x70, 0xbb, 0xe5, 0x27, 0xae, 0x24, 0x7e, 0xe5,
                0x94, 0x00, 0x5f, 0x95, 0x2d, 0xac, 0xd1, 0xd0, 0x15, 0x8f, 0x81, 0xee, 0x6e, 0x71, 0x71, 0x33, 0xa4,
                0xea, 0xfa, 0x36, 0x08, 0xda, 0xf4, 0x80, 0x33, 0xb1, 0xfa, 0x9d, 0x76, 0x90,
            ])
            #expect(template.secret == expectedSecret)
        } catch {
            Issue.record("Failed with error: \(error)")
        }
    }

    @Test func missingSchemeWithURL() throws {
        let url = URL(string: "http://totp/Issuer-in-path:john@example.com?secret=HXDM")!
        do {
            _ = try OATHSession.CredentialTemplate(withURL: url)
            Issue.record("Parsed url with wrong scheme.")
        } catch {
            if case OATHSession.CredentialTemplateError.missingScheme = error {
                print("Function throwed expected error: \(error)")
            } else {
                Issue.record("Funktion throwed unexpeced error: \(error)")
            }
        }
    }

    @Test func malformedTypeWithURL() throws {
        let url = URL(string: "otpauth://footp/Issuer-in-path:john@example.com?secret=HXDM")!
        do {
            _ = try OATHSession.CredentialTemplate(withURL: url)
            Issue.record("Parsed url with malformed type.")
        } catch {
            if case OATHSession.CredentialTemplateError.parseType = error {
                print("Function throwed expected error: \(error)")
            } else {
                Issue.record("Funktion throwed unexpeced error: \(error)")
            }
        }
    }

    @Test func missingNameWithURL() throws {
        let url = URL(string: "otpauth://totp/?secret=HXDM")!
        do {
            _ = try OATHSession.CredentialTemplate(withURL: url)
            Issue.record("Parsed url with missing name.")
        } catch {
            if case OATHSession.CredentialTemplateError.missingName = error {
                print("Function throwed expected error: \(error)")
            } else {
                Issue.record("Funktion throwed unexpeced error: \(error)")
            }
        }
    }

    @Test func missingSecretWithURL() throws {
        let url = URL(string: "otpauth://totp/Issuer-in-path:john@example.com")!
        do {
            _ = try OATHSession.CredentialTemplate(withURL: url)
            Issue.record("Parsed url with missing secret.")
        } catch {
            if case OATHSession.CredentialTemplateError.missingSecret = error {
                print("Function throwed expected error: \(error)")
            } else {
                Issue.record("Funktion throwed unexpeced error: \(error)")
            }
        }
    }

    @Test func malformedAlgorithmWithURL() throws {
        let url = URL(string: "otpauth://totp/Issuer-in-path:john@example.com?secret=HXDM&algorithm=SHA42")!
        do {
            _ = try OATHSession.CredentialTemplate(withURL: url)
            Issue.record("Parsed url with malformed algorithm.")
        } catch {
            if case OATHSession.CredentialTemplateError.parseAlgorithm = error {
                print("Function throwed expected error: \(error)")
            } else {
                Issue.record("Funktion throwed unexpeced error: \(error)")
            }
        }
    }
}
