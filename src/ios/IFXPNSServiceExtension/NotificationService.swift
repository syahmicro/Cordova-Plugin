//
//  NotificationService.swift
//  IFXPNSServiceExtension
//
//  Created by IFXDevMob on 21/06/2023.
//

import UserNotifications

class NotificationService: UNNotificationServiceExtension {

    var contentHandler: ((UNNotificationContent) -> Void)?
    var bestAttemptContent: UNMutableNotificationContent?

    override func didReceive(_ request: UNNotificationRequest, withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
        self.contentHandler = contentHandler
        bestAttemptContent = (request.content.mutableCopy() as? UNMutableNotificationContent)
        
        struct IFXPNSContent: Codable {
            let title: String
            let body: String
            let pageId: String
            let action: String
        }
        
        if let bestAttemptContent = bestAttemptContent {
            print("Inside NotificationService")
            // Modify the notification content here...
            print("Inside NotificationService")
                        
            var encryptionHandler:EncryptionServiceHandler = EncryptionServiceHandler()
            var toDecrypt:String = bestAttemptContent.userInfo["ifx"] as? String ?? "ERR"
            
            print("Text to decrypt")
            print(toDecrypt)
            let decrypted = encryptionHandler.decrypt(encryptedString: toDecrypt)
            
            do {
                let jsonData = decrypted.data(using: .utf8)!
                let payload = try JSONDecoder().decode(IFXPNSContent.self, from: jsonData)
                
                // Modify the notification content here...
                bestAttemptContent.title = "Test Title"
                bestAttemptContent.body =  "Test Body"
                
                print("Custom payload pageId " + payload.pageId)
                print("Custom payload action " + payload.action)
                
            } catch {
                print("Error: \(error)")
                bestAttemptContent.title = "Decrypt Failed"
                bestAttemptContent.body =  error.localizedDescription
                
            }
            
            contentHandler(bestAttemptContent)
        }
    }
    
    override func serviceExtensionTimeWillExpire() {
        // Called just before the extension will be terminated by the system.
        // Use this as an opportunity to deliver your "best attempt" at modified content, otherwise the original push payload will be used.
        if let contentHandler = contentHandler, let bestAttemptContent =  bestAttemptContent {
            contentHandler(bestAttemptContent)
        }
    }

}
