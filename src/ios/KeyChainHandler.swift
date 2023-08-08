//
//  KeyChainHandler.swift
//  App
//
//  Created by IFXDevMob on 21/06/2023.
//

import Foundation

class KeyChainHandler {
    @objc func get(_ key: String) -> String {
        // Set query
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "cap_sec",
            kSecAttrAccount as String: key,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true,
        ]
        
        var item: CFTypeRef?
        // Check if user exists in the keychain
        if SecItemCopyMatching(query as CFDictionary, &item) == noErr {
            // Extract result
            if let existingItem = item as? [String: Any],
               let valData = existingItem[kSecValueData as String] as? Data,
               let valStr = String(data: valData, encoding: .utf8)
            {
                print("Keychain value for \(key)")
                print(valStr)
                
                return valStr
            }
        } else {
            print("Something went wrong trying to find the user in the keychain")
        }
        
        return "err"
    }
}


