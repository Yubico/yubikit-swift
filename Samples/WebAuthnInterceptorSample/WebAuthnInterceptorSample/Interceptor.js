// Interceptor.js - WebAuthn API Interceptor
//
// Monkey-patches navigator.credentials.create() and navigator.credentials.get()
// to route WebAuthn requests through native Swift via WebKit message handlers.
// Data is base64-encoded in both directions to avoid escaping issues.

(function() {
    'use strict';

    // MARK: - Setup

    const originalCreate = navigator.credentials.create.bind(navigator.credentials);
    const originalGet = navigator.credentials.get.bind(navigator.credentials);

    let pendingResolve = null;
    let pendingReject = null;

    // MARK: - Native Callbacks

    window.__webauthn_callback__ = function(encoded) {
        console.log('[WebAuthn] Received success callback');
        if (pendingResolve) {
            try {
                const response = JSON.parse(atob(encoded));
                const credential = decodeCredential(response);
                pendingResolve(credential);
            } catch (e) {
                pendingReject(new DOMException(e.message, 'NotAllowedError'));
            }
            pendingResolve = null;
            pendingReject = null;
        }
    };

    window.__webauthn_error__ = function(encoded) {
        const errorMessage = atob(encoded);
        console.log('[WebAuthn] Received error:', errorMessage);
        if (pendingReject) {
            pendingReject(new DOMException(errorMessage, 'NotAllowedError'));
            pendingResolve = null;
            pendingReject = null;
        }
    };

    // MARK: - Binary Decoding (Swift → JS)

    function base64urlDecode(str) {
        str = str.replace(/-/g, '+').replace(/_/g, '/');
        while (str.length % 4) str += '=';
        const binary = atob(str);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    // Recursively decode all {"__binary__": "..."} markers to ArrayBuffer
    function decodeBinaryValues(obj) {
        if (obj === null || obj === undefined) return obj;
        if (typeof obj !== 'object') return obj;
        if (Array.isArray(obj)) return obj.map(decodeBinaryValues);
        if (obj.__binary__ !== undefined) return base64urlDecode(obj.__binary__);
        const result = {};
        for (const key of Object.keys(obj)) {
            result[key] = decodeBinaryValues(obj[key]);
        }
        return result;
    }

    // MARK: - Binary Encoding (JS → Swift)

    function base64urlEncode(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    function encodeRequest(options) {
        return JSON.parse(JSON.stringify(options, (key, value) => {
            if (value instanceof ArrayBuffer) {
                return base64urlEncode(value);
            }
            if (value instanceof Uint8Array) {
                return base64urlEncode(value.buffer);
            }
            return value;
        }));
    }

    // MARK: - Credential Decoding

    function decodeCredential(response) {
        // Decode all binary fields in one pass
        const decoded = decodeBinaryValues(response);

        const credential = {
            id: response.id,
            rawId: decoded.rawId,
            type: decoded.type,
            authenticatorAttachment: decoded.authenticatorAttachment,
            getClientExtensionResults: function() {
                return decoded.clientExtensionResults || {};
            }
        };

        // Build response object
        credential.response = {
            clientDataJSON: decoded.response.clientDataJSON
        };

        // MakeCredential response fields
        if (decoded.response.attestationObject) {
            credential.response.attestationObject = decoded.response.attestationObject;
            credential.response.getTransports = function() {
                return response.response.transports || [];
            };
            credential.response.getAuthenticatorData = function() {
                return decoded.response.authenticatorData;
            };
            credential.response.getPublicKey = function() {
                // This sample does not implement SPKI encoding for getPublicKey().
                // RPs that require the public key should extract it from attestationObject
                // or extend the native implementation to provide SPKI-encoded key data.
                console.warn('[WebAuthn] getPublicKey() is not implemented in this sample and returns null');
                return null;
            };
            credential.response.getPublicKeyAlgorithm = function() {
                return response.response.publicKeyAlgorithm || -7;
            };
        }

        // GetAssertion response fields
        if (decoded.response.signature) {
            credential.response.authenticatorData = decoded.response.authenticatorData;
            credential.response.signature = decoded.response.signature;
            // Per spec, userHandle should be null (not undefined) when absent
            credential.response.userHandle = decoded.response.userHandle ?? null;
        }

        return credential;
    }

    // MARK: - Interception

    function shouldIntercept(options) {
        // Intercept all WebAuthn requests and route them to the YubiKey.
        // To only intercept when security-key hint is present, use:
        // return Array.isArray(options?.publicKey?.hints) && options.publicKey.hints.includes('security-key');
        return options?.publicKey != null;
    }

    function interceptWebAuthn(type, options, originalFn) {
        if (!shouldIntercept(options)) {
            console.log('[WebAuthn] Forwarding to OS');
            return originalFn(options);
        }

        console.log(`[WebAuthn] Intercepting ${type}`);

        return new Promise((resolve, reject) => {
            pendingResolve = resolve;
            pendingReject = reject;

            const request = {
                type: type,
                origin: window.location.origin,
                request: encodeRequest(options.publicKey)
            };

            window.webkit.messageHandlers[`__webauthn_${type}__`].postMessage(btoa(JSON.stringify(request)));
        });
    }

    // MARK: - API Patching

    navigator.credentials.create = function(options) {
        return interceptWebAuthn('create', options, originalCreate);
    };

    navigator.credentials.get = function(options) {
        return interceptWebAuthn('get', options, originalGet);
    };

    // Override platform authenticator checks since we route to YubiKey
    if (window.PublicKeyCredential) {
        window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = function() {
            return Promise.resolve(false);
        };
        window.PublicKeyCredential.isConditionalMediationAvailable = function() {
            return Promise.resolve(false);
        };
    }

    console.log('[WebAuthn] Interceptor installed');
})();
