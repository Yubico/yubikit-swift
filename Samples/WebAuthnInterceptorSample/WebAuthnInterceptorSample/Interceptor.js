// Interceptor.js - WebAuthn API Interceptor
//
// Monkey-patches navigator.credentials.create() and navigator.credentials.get()
// to route WebAuthn requests through native Swift via WebKit message handlers.
//
// WebAuthn Level 3 only provides JSON serialization in one direction (credential.toJSON()).
// This interceptor implements the inverse: options → JSON and JSON → credential.

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
                const credential = parsePublicKeyCredentialFromJSON(response);
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

    // MARK: - Base64URL Encoding

    function base64urlToArrayBuffer(str) {
        let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) base64 += '=';
        return Uint8Array.from(atob(base64), c => c.charCodeAt(0)).buffer;
    }

    // Note: Spread operator may hit stack limits for very large ArrayBuffers.
    // Typical WebAuthn payloads are well under this limit.
    function arrayBufferToBase64url(buffer) {
        return btoa(String.fromCharCode(...new Uint8Array(buffer)))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function serializePublicKeyOptionsToJSON(options) {
        return JSON.parse(JSON.stringify(options, (key, value) => {
            if (value instanceof ArrayBuffer) return arrayBufferToBase64url(value);
            if (value instanceof Uint8Array) return arrayBufferToBase64url(value.buffer);
            return value;
        }));
    }

    function decodeExtensionResults(ext) {
        if (!ext) return {};

        if (ext.prf && ext.prf.results) {
            if (ext.prf.results.first) ext.prf.results.first = base64urlToArrayBuffer(ext.prf.results.first);
            if (ext.prf.results.second) ext.prf.results.second = base64urlToArrayBuffer(ext.prf.results.second);
        }

        if (ext.largeBlob && ext.largeBlob.blob) {
            ext.largeBlob.blob = base64urlToArrayBuffer(ext.largeBlob.blob);
        }

        if (ext.previewSign) {
            if (ext.previewSign.generatedKey) {
                const gk = ext.previewSign.generatedKey;
                if (gk.keyHandle) gk.keyHandle = base64urlToArrayBuffer(gk.keyHandle);
                if (gk.publicKey) gk.publicKey = base64urlToArrayBuffer(gk.publicKey);
                if (gk.attestationObject) gk.attestationObject = base64urlToArrayBuffer(gk.attestationObject);
            }
            if (ext.previewSign.signature) {
                ext.previewSign.signature = base64urlToArrayBuffer(ext.previewSign.signature);
            }
        }

        return ext;
    }

    function parsePublicKeyCredentialFromJSON(json) {
        const extensionResults = decodeExtensionResults(json.clientExtensionResults || {});

        const credential = {
            id: json.id,
            rawId: base64urlToArrayBuffer(json.rawId),
            type: json.type,
            authenticatorAttachment: json.authenticatorAttachment,
            getClientExtensionResults: () => extensionResults,
            toJSON: () => json  // WebAuthn Level 3: returns base64url strings directly
        };

        credential.response = {
            clientDataJSON: base64urlToArrayBuffer(json.response.clientDataJSON),
            toJSON: () => json.response
        };

        // Registration response
        if (json.response.attestationObject) {
            credential.response.attestationObject = base64urlToArrayBuffer(json.response.attestationObject);
            credential.response.getTransports = () => json.response.transports || [];
            credential.response.getAuthenticatorData = () => base64urlToArrayBuffer(json.response.authenticatorData);
            credential.response.getPublicKey = () => json.response.publicKey
                ? base64urlToArrayBuffer(json.response.publicKey) : null;
            credential.response.getPublicKeyAlgorithm = () => json.response.publicKeyAlgorithm;
        }

        // Authentication response
        if (json.response.signature) {
            credential.response.authenticatorData = base64urlToArrayBuffer(json.response.authenticatorData);
            credential.response.signature = base64urlToArrayBuffer(json.response.signature);
            // Per spec, userHandle should be null (not undefined) when absent
            credential.response.userHandle = json.response.userHandle
                ? base64urlToArrayBuffer(json.response.userHandle)
                : null;
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

            const publicKey = serializePublicKeyOptionsToJSON(options.publicKey);

            // Per WebAuthn spec: rp.id defaults to origin's effective domain
            if (type === 'create' && publicKey.rp && !publicKey.rp.id) {
                publicKey.rp.id = window.location.hostname;
            }

            const request = {
                type: type,
                origin: window.location.origin,
                request: publicKey
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
        window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = () => Promise.resolve(false);
        window.PublicKeyCredential.isConditionalMediationAvailable = () => Promise.resolve(false);
    }

    // Forward console.log to native for debugging
    const originalLog = console.log;
    const originalError = console.error;
    const originalWarn = console.warn;
    console.log = function(...args) {
        originalLog.apply(console, args);
        window.webkit.messageHandlers.__webauthn_console__.postMessage(args.map(String).join(' '));
    };
    console.error = function(...args) {
        originalError.apply(console, args);
        window.webkit.messageHandlers.__webauthn_console__.postMessage('[ERROR] ' + args.map(String).join(' '));
    };
    console.warn = function(...args) {
        originalWarn.apply(console, args);
        window.webkit.messageHandlers.__webauthn_console__.postMessage('[WARN] ' + args.map(String).join(' '));
    };

    console.log('[WebAuthn] Interceptor installed');
})();
