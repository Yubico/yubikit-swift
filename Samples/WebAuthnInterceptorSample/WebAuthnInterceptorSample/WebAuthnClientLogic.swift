//
//  WebAuthnClientLogic.swift
//  WebAuthnInterceptorSample
//
//  TODO: Move this to the SDK as a WebAuthn.Client API.
//
//  This file contains WebAuthn client-level logic that bridges between WebAuthn API requests
//  and CTAP2 SDK calls. Currently lives in the sample app, but should eventually be part of
//  the SDK to simplify WebAuthn implementations.
//
//  What this file handles:
//  - Building CTAP2 extension inputs from WebAuthn extension requests
//  - Extracting WebAuthn extension results from CTAP2 responses
//  - LargeBlob orchestration (key retrieval + blob read/write)
//  - Extension state tracking across request/response
//

import Foundation
import YubiKit

// MARK: - Extension State

/// State for tracking extensions during makeCredential.
struct CreateExtensionState {
    var inputs: [CTAP2.Extension.MakeCredential.Input] = []
    var credProtect: CTAP2.Extension.CredProtect?
    var prf: WebAuthn.Extension.PRF?
    var largeBlobKey: CTAP2.Extension.LargeBlobKey?
}

/// State for tracking extensions during getAssertion.
struct GetExtensionState {
    var inputs: [CTAP2.Extension.GetAssertion.Input] = []
    var prf: WebAuthn.Extension.PRF?
    var largeBlobKey: CTAP2.Extension.LargeBlobKey?
    var largeBlobRead: Bool = false
    var largeBlobWrite: Data?
}

// MARK: - Extension Input Building

/// Builds CTAP2 extension inputs from a WebAuthn create request.
func buildCreateExtensions(
    request: CreateRequest,
    session: CTAP2.Session
) async throws -> CreateExtensionState {
    var state = CreateExtensionState()

    // credProtect extension
    if let credProtectLevel = request.extensions?.credProtect,
        let level = CTAP2.Extension.CredProtect.Level(rawValue: credProtectLevel)
    {
        trace("Adding credProtect extension with level \(credProtectLevel)")
        let credProtect = try await CTAP2.Extension.CredProtect(level: level, session: session)
        state.inputs.append(credProtect.input())
        state.credProtect = credProtect
    }

    // PRF extension (with or without secrets)
    if let prfEval = request.extensions?.prf?.eval,
        let firstData = Data(base64urlDecoding: prfEval.first)
    {
        trace("Adding PRF extension for makeCredential with secrets")
        let prf = try await WebAuthn.Extension.PRF(session: session)
        let secondData = prfEval.second.flatMap { Data(base64urlDecoding: $0) }
        state.inputs.append(try prf.makeCredential.input(first: firstData, second: secondData))
        state.prf = prf
    } else if request.extensions?.hmacCreateSecret == true || request.extensions?.prf != nil {
        trace("Adding PRF extension for makeCredential (enable only)")
        let prf = try await WebAuthn.Extension.PRF(session: session)
        state.inputs.append(prf.makeCredential.input())
        state.prf = prf
    }

    // largeBlob extension
    if let support = request.extensions?.largeBlob?.support,
        support == "required" || support == "preferred"
    {
        trace("Adding largeBlobKey extension for makeCredential (support: \(support))")
        let largeBlobKey = CTAP2.Extension.LargeBlobKey()
        state.inputs.append(largeBlobKey.makeCredential.input())
        state.largeBlobKey = largeBlobKey
    }

    return state
}

/// Builds CTAP2 extension inputs from a WebAuthn get request.
func buildGetExtensions(
    request: GetRequest,
    session: CTAP2.Session
) async throws -> GetExtensionState {
    var state = GetExtensionState()

    // PRF extension
    if let prfEval = request.extensions?.prf?.eval,
        let firstData = Data(base64urlDecoding: prfEval.first)
    {
        trace("Adding PRF extension")
        let prf = try await WebAuthn.Extension.PRF(session: session)
        let secondData = prfEval.second.flatMap { Data(base64urlDecoding: $0) }
        state.inputs.append(try prf.getAssertion.input(first: firstData, second: secondData))
        state.prf = prf
    }

    // largeBlob extension (read or write)
    let wantsRead = request.extensions?.largeBlob?.read == true
    let writeData = request.extensions?.largeBlob?.write.flatMap { Data(base64urlDecoding: $0) }
    if wantsRead || writeData != nil {
        trace("Adding largeBlobKey extension for getAssertion (read: \(wantsRead), write: \(writeData != nil))")
        let largeBlobKey = CTAP2.Extension.LargeBlobKey()
        state.inputs.append(largeBlobKey.getAssertion.input())
        state.largeBlobKey = largeBlobKey
        state.largeBlobRead = wantsRead
        state.largeBlobWrite = writeData
    }

    return state
}

// MARK: - Extension Result Extraction

/// Extracts WebAuthn extension results from a makeCredential response.
func extractCreateExtensionResults(
    state: CreateExtensionState,
    response: CTAP2.MakeCredential.Response
) throws -> ExtensionResults {
    var results = ExtensionResults()

    if let credProtect = state.credProtect, let level = credProtect.output(from: response) {
        trace("credProtect applied with level \(level.rawValue)")
        results.credProtect = level.rawValue
    }

    if let prf = state.prf, let prfResult = try prf.makeCredential.output(from: response) {
        trace("PRF extension result received")
        results.prf = PRFOutput(prfResult)
    }

    if let largeBlobKey = state.largeBlobKey {
        let key = largeBlobKey.makeCredential.output(from: response)
        trace("largeBlobKey extension: \(key != nil ? "supported" : "not supported")")
        results.largeBlob = .supported(key != nil)
    }

    return results
}

/// Extracts WebAuthn extension results from a getAssertion response.
/// Also handles largeBlob read/write operations which require additional CTAP calls.
func extractGetExtensionResults(
    state: GetExtensionState,
    response: CTAP2.GetAssertion.Response,
    session: CTAP2.Session,
    pinToken: CTAP2.ClientPin.Token?
) async throws -> ExtensionResults {
    var results = ExtensionResults()

    if let prf = state.prf, let secrets = try prf.getAssertion.output(from: response) {
        trace("PRF extension returned secrets")
        results.prf = PRFOutput(secrets)
    }

    // Handle largeBlob read/write
    if let largeBlobKey = state.largeBlobKey,
        let key = largeBlobKey.getAssertion.output(from: response)
    {
        if state.largeBlobRead {
            trace("Reading largeBlob...")
            let blob = try await session.getBlob(key: key)
            trace("largeBlob read: \(blob != nil ? "\(blob!.count) bytes" : "no blob found")")
            results.largeBlob = .read(blob)
        } else if let writeData = state.largeBlobWrite, let pinToken {
            trace("Writing largeBlob (\(writeData.count) bytes)...")
            try await session.putBlob(key: key, data: writeData, pinToken: pinToken)
            trace("largeBlob write successful")
            results.largeBlob = .written(true)
        }
    } else if state.largeBlobKey != nil {
        trace("largeBlobKey not returned by authenticator")
        if state.largeBlobRead {
            results.largeBlob = .read(nil)
        } else if state.largeBlobWrite != nil {
            results.largeBlob = .written(false)
        }
    }

    return results
}

// MARK: - Permission Calculation

/// Calculates the CTAP2 permissions needed for a getAssertion request.
func permissionsForGetAssertion(request: GetRequest) -> CTAP2.ClientPin.Permission {
    var permissions: CTAP2.ClientPin.Permission = .getAssertion

    if request.extensions?.largeBlob?.write != nil {
        permissions.insert(.largeBlobWrite)
    }

    return permissions
}
