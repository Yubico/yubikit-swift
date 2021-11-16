//
//  OATHModel.swift
//  OATHSample
//
//  Created by Jens Utbult on 2021-11-16.
//

import Foundation
import YubiKit

class OATHModel: ObservableObject {
    @Published private(set) var code = "?"
    @Published private(set) var errorMessage: String?
    
    @MainActor func calculateCode() {
        Task {
            errorMessage = nil
            code = "?"
            do {
                let connection = try await Connection.connection()
                let session = try await connection.session()
                code = try await session.calculateCode()
            } catch let error {
                errorMessage = error.localizedDescription
            }
        }
    }
}
