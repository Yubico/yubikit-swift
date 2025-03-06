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

import Foundation
import CryptoKit

public struct StaticKeys {
    
    private static let defaultKey: Data = Data([0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                                                0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f])
        
    let enc: Data
    let mac: Data
    let dek: Data?
    
    init(enc: Data, mac: Data, dek: Data?) {
        self.enc =  enc
        self.mac = mac
        self.dek = dek
    }
    
    func derive(context: Data) -> SCPSessionKeys {
        return SCPSessionKeys(senc: try! Self.deriveKey(key: enc, t: 0x4, context: context, l: 0x80),
                              smac: try! Self.deriveKey(key: mac, t: 0x6, context: context, l: 0x80),
                              srmac: try! Self.deriveKey(key: mac, t: 0x7, context: context, l: 0x80),
                              dek: dek
        )
    }
    
    static func defaultKeys() -> StaticKeys {
        StaticKeys(enc: defaultKey, mac: defaultKey, dek: defaultKey)
    }
    
    internal static func deriveKey(key:  Data, t: Int8, context: Data, l: Int16) throws -> Data {
        guard l == 0x40 || l == 0x80 else { throw "Invalid argument" }
        
        var i = Data(count: 11)
        i.append(t.data)
        i.append(UInt8(0).data)
        i.append(l.bigEndian.data)
        i.append(UInt8(1).data)
        i.append(context)
        
        let digest = try i.aescmac(key: key)
        return digest.prefix(Int(l/8))
    }
}


/*
 
 
 static SecretKey deriveKey(SecretKey key, byte t, byte[] context, short l) {
     if (!(l == 0x40 || l == 0x80)) {
         throw new IllegalArgumentException("l must be 0x40 or 0x80");
     }
     byte[] i = ByteBuffer.allocate(16 + context.length)
             .put(new byte[11])
             .put(t).put((byte) 0)
             .putShort(l)
             .put((byte) 1)
             .put(context)
             .array();

     byte[] digest = null;
     try {
         Mac mac = Mac.getInstance("AESCMAC");
         mac.init(key);
         digest = mac.doFinal(i);
         return new SecretKeySpec(digest, 0, l / 8, "AES");
     } catch (NoSuchAlgorithmException | InvalidKeyException e) {
         throw new UnsupportedOperationException("Cryptography provider does not support AESCMAC", e);
     } finally {
         if (digest != null) {
             Arrays.fill(digest, (byte) 0);
         }
     }
 }
import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class StaticKeys {
    private static final byte[] DEFAULT_KEY = new byte[]{
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
    };

    final SecretKey enc;
    final SecretKey mac;
    @Nullable final SecretKey dek;

    public StaticKeys(byte[] enc, byte[] mac, @Nullable byte[] dek) {
        this.enc = new SecretKeySpec(enc, "AES");
        this.mac = new SecretKeySpec(mac, "AES");
        this.dek = dek != null ? new SecretKeySpec(dek, "AES") : null;
    }

    public SessionKeys derive(byte[] context) {
        return new SessionKeys(
                deriveKey(enc, (byte) 0x4, context, (short) 0x80),
                deriveKey(mac, (byte) 0x6, context, (short) 0x80),
                deriveKey(mac, (byte) 0x7, context, (short) 0x80),
                dek
        );
    }

    public static StaticKeys getDefaultKeys() {
        return new StaticKeys(DEFAULT_KEY, DEFAULT_KEY, DEFAULT_KEY);
    }


}
*/
