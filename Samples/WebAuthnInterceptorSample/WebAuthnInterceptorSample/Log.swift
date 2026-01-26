//
//  Log.swift
//  WebAuthnInterceptorSample
//
//  Simple error logging for debugging.
//

import Foundation

func logError(_ message: String, file: String = #file, line: Int = #line) {
    let filename = (file as NSString).lastPathComponent
    print("[ERROR] \(filename):\(line) - \(message)")
}
