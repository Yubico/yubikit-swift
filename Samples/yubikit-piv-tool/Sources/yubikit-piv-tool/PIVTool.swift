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

import ArgumentParser
import Foundation
import YubiKit

// A PIV management tool built in Swift with YubiKit SDK.
@main
struct PIVTool: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "yubikit-piv-tool",
        abstract: "YubiKey SDK PIV tool (Sample App)",
        discussion: """
            A Swift-based PIV management tool.
            """,
        subcommands: [
            List.self,
            Info.self,
            Reset.self,
            Access.self,
            Keys.self,
            Certificates.self,
        ]
    )

    // Override to handle custom errors
    static func main() async {
        do {
            var command = try PIVTool.parseAsRoot()
            if var asyncCommand = command as? AsyncParsableCommand {
                try await asyncCommand.run()
            } else {
                try command.run()
            }
            Foundation.exit(EXIT_SUCCESS)
        } catch let error as PIVToolError {
            fputs("Error: \(error.description)\n", stderr)
            Foundation.exit(EXIT_FAILURE)
        } catch {
            if let errorDescription = error.mappedDescription {
                fputs("Error: \(errorDescription)\n", stderr)
                Foundation.exit(EXIT_FAILURE)
            }

            // ArgumentParser handles its own errors
            exit(withError: error)
        }
    }
}
