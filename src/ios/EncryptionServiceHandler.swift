//
//  EncryptionServiceHandler.swift
//  App
//
//  Created by IFXDevMob on 21/06/2023.
//

import Foundation
import Security


class EncryptionServiceHandler {
    
    func removeHeaderFooterAndNewlines(from pemString: String) -> String? {
        // Define regular expressions
        let headerRegex = try! NSRegularExpression(pattern: "-----BEGIN RSA PRIVATE KEY-----\r\n", options: [])
        let footerRegex = try! NSRegularExpression(pattern: "-----END RSA PRIVATE KEY-----\r\n", options: [])
        let newlineRegex = try! NSRegularExpression(pattern: "\r\n", options: [])

        // Remove header
        let headerRange = NSRange(location: 0, length: pemString.count)
        let withoutHeader = headerRegex.stringByReplacingMatches(in: pemString, options: [], range: headerRange, withTemplate: "")

        // Remove footer
        let footerRange = NSRange(location: 0, length: withoutHeader.count)
        let withoutHeaderAndFooter = footerRegex.stringByReplacingMatches(in: withoutHeader, options: [], range: footerRange, withTemplate: "")

        // Remove newlines
        let newlineRange = NSRange(location: 0, length: withoutHeaderAndFooter.count)
        let withoutNewlines = newlineRegex.stringByReplacingMatches(in: withoutHeaderAndFooter, options: [], range: newlineRange, withTemplate: "")
        
        var replaced = pemString.replacingOccurrences(of: "-----BEGIN RSA PRIVATE KEY-----\r\n", with: "")
        replaced = replaced.replacingOccurrences(of: "-----END RSA PRIVATE KEY-----\r\n", with: "")
        replaced = replaced.replacingOccurrences(of: "\r\n", with: "")

        return replaced
    }
    
    func getKeySize(key: SecKey) -> Int? {
        guard let keyData = SecKeyCopyExternalRepresentation(key, nil) as Data? else {
            return nil
        }
        
        let keySize = keyData.count * 8
        return keySize
    }
    
    func convertCFDataArrayToString(_ dataArray: [CFData]) -> String {
        var stringArray: [String] = []
        
        for data in dataArray {
            let bytePtr = CFDataGetBytePtr(data)
            let length = CFDataGetLength(data)
            let dataBytes = UnsafeBufferPointer(start: bytePtr, count: length)
            let dataBuffer = Data(buffer: dataBytes)
            
            if let string = String(data: dataBuffer, encoding: .utf8) {
                stringArray.append(string)
            }
        }
        
        return stringArray.joined()
    }
    
    func initDecrypt(toDecrypt: String, privateKey: SecKey) -> String {
        let BLOCKSIZE = 256
        do {
            var list: [CFData] = []
            guard let array = Data(base64Encoded: toDecrypt) else { return "" }
            
            let collection = try decrypt(array, keySize: 2048, privateKey: privateKey, fOAEP: false)
            list.append(collection)
            
            return convertCFDataArrayToString(list)
        } catch {
            return ""
        }
    }
    
    func decrypt(_ rgb: Data, keySize:Int, privateKey: SecKey, fOAEP: Bool) throws -> CFData {
        if rgb.isEmpty {
            throw NSError(domain: "DecryptionError", code: 0, userInfo: [NSLocalizedDescriptionKey: "The 'rgb' parameter is nil."])
        }
        
        let keySizeInBytes = keySize / 8
        if rgb.count > keySizeInBytes {
            throw NSError(domain: "DecryptionError", code: 0, userInfo: [NSLocalizedDescriptionKey: "The data to be decrypted exceeds the maximum for this modulus of \(keySizeInBytes) bytes."])
        }
        var error: Unmanaged<CFError>?
        
        guard let decryptedData = SecKeyCreateDecryptedData(privateKey, .rsaEncryptionPKCS1, rgb as CFData, &error) as CFData? else {
            let errorMessage = error?.takeRetainedValue() as CFError?
            print("Error: \(errorMessage)")
            throw NSError(domain: "DecryptionError", code: 0, userInfo: [NSLocalizedDescriptionKey: "Error: \(errorMessage)"])
        }
        
        return try decryptedData
    }

    @objc func decrypt(encryptedString:String)->String
    {
        var kcHandler:KeyChainHandler = KeyChainHandler()
        print("Getting keychain data")
        var privateKey:String = kcHandler.get("IFXPNSPrivPem")

        var error: Unmanaged<CFError>?
        let keyStringWithoutHeaderFooter = removeHeaderFooterAndNewlines(from: privateKey) ?? ""
        let privateKeyData = Data(base64Encoded: keyStringWithoutHeaderFooter)!
        let privateKeyAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: "2048"
            
        ]
        
        guard let privateKey = SecKeyCreateWithData(privateKeyData as CFData, privateKeyAttributes as CFDictionary, &error) else {
            let errorMessage = error?.takeRetainedValue() as Error?
            print("Error: \(errorMessage)")
            return "Error: \(errorMessage)"
        }
        
        // Decrypt the encrypted string
        let decryptedString = initDecrypt(toDecrypt: encryptedString, privateKey: privateKey)
        if decryptedString.contains("Error") {
            print("Decrypted string: \(decryptedString)")
        } else {
            print("Decryption failed")
        }
        
        return decryptedString
    }
}
