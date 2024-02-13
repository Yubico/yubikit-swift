//
//  PIVSessionFeature.swift
//  YubiKit
//
//  Created by Jens Utbult on 2024-02-12.
//

import Foundation

public enum PIVSessionFeature: SessionFeature {
    
    case usagePolicy, aesKey, serialNumber, metadata, attestation, p384, touchCached, rsaGeneration
     
    public func isSupported(by version: Version) -> Bool {
        switch self {
        case .usagePolicy:
            return version >= Version(withString: "4.0.0")!
        case .aesKey:
            return version >= Version(withString: "5.4.0")!
        case .serialNumber:
            return version >= Version(withString: "5.0.0")!
        case .metadata:
            return version >= Version(withString: "5.3.0")!
        case .attestation:
            return version >= Version(withString: "4.3.0")!
        case .p384:
            return version >= Version(withString: "4.0.0")!
        case .touchCached:
            return version >= Version(withString: "4.3.0")!
        case .rsaGeneration:
            return version < Version(withString: "4.2.6")! || version >= Version(withString: "4.3.5")!
        }
    }
}
