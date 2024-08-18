//
//  ECCManager.swift
//  EllipticCurveCryptography
//
//  Created by AK on 8/18/24.
//

import Foundation
import Security

class ECCManager {
    
    private let tag: String
    private let keyType = kSecAttrKeyTypeECSECPrimeRandom
    private let keySize = 256
    
    init(tag: String) {
        self.tag = tag
    }
    
    private func keyQuery() -> [String: Any] {
        
        return [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: keyType,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true
        ]
    }
    
    func generateKeyPair() throws {
            let privateKeyParams: [String: Any] = [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag
            ]

            let parameters: [String: Any] = [
                kSecAttrKeyType as String: keyType,
                kSecAttrKeySizeInBits as String: keySize,
                kSecPrivateKeyAttrs as String: privateKeyParams
            ]

            var error: Unmanaged<CFError>?
            guard let privateKey = SecKeyCreateRandomKey(parameters as CFDictionary, &error) else {
                throw error!.takeRetainedValue() as Error
            }

            // Store the public key in the keychain
            if let publicKey = SecKeyCopyPublicKey(privateKey) {
                try savePublicKey(publicKey)
            }
        }
    
    private func savePublicKey(_ publicKey: SecKey) throws {
            var error: Unmanaged<CFError>?
            let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error)

            guard let data = publicKeyData as Data? else {
                throw error!.takeRetainedValue() as Error
            }

            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: tag + ".publicKey",
                kSecAttrKeyType as String: keyType,
                kSecValueData as String: data,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                kSecAttrIsPermanent as String: true
            ]

            let status = SecItemAdd(query as CFDictionary, nil)

            if status != errSecSuccess && status != errSecDuplicateItem {
                throw NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: nil)
            }
        }
    
    private func getPrivateKey() throws -> SecKey? {
           var query = keyQuery()
           query[kSecAttrKeyClass as String] = kSecAttrKeyClassPrivate

           var item: CFTypeRef?
           let status = SecItemCopyMatching(query as CFDictionary, &item)

           guard status == errSecSuccess else {
               throw NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: nil)
           }

           return (item as! SecKey)
       }
    

    
    func getPublicKey() throws -> SecKey? {
            let query = keyQuery()
            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)

            guard status == errSecSuccess else {
                throw NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: nil)
            }

            guard let privateKey = item else {
                throw NSError(domain: NSOSStatusErrorDomain, code: Int(errSecItemNotFound), userInfo: nil)
            }

        return SecKeyCopyPublicKey(privateKey as! SecKey)
        }

    
    
    
    func sign(data: Data) throws -> Data? {
            guard let privateKey = try getPrivateKey() else {
                return nil
            }

            var error: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(privateKey,
                                                        .ecdsaSignatureDigestX962SHA256,
                                                        data as CFData,
                                                        &error) else {
                throw error!.takeRetainedValue() as Error
            }

            return signature as Data
        }
    
    func verify(data: Data, signature: Data) throws -> Bool {
            guard let publicKey = try getPublicKey() else {
                return false
            }

            var error: Unmanaged<CFError>?
            let status = SecKeyVerifySignature(publicKey,
                                               .ecdsaSignatureDigestX962SHA256,
                                               data as CFData,
                                               signature as CFData,
                                               &error)

            if let error = error {
                throw error.takeRetainedValue() as Error
            }

            return status
        }
    
    
    func encrypt(data: Data) throws -> Data? {
            guard let publicKey = try getPublicKey() else {
                throw NSError(domain: NSOSStatusErrorDomain, code: Int(errSecItemNotFound), userInfo: nil)
            }

            var error: Unmanaged<CFError>?
            guard let encryptedData = SecKeyCreateEncryptedData(publicKey,
                                                                .eciesEncryptionStandardX963SHA256AESGCM,
                                                                data as CFData,
                                                                &error) else {
                throw error!.takeRetainedValue() as Error
            }

            return encryptedData as Data
        }
    
    func decrypt(data: Data) throws -> Data? {
        
            guard let privateKey = try getPrivateKey() else {
                return nil
            }

            var error: Unmanaged<CFError>?
            guard let decryptedData = SecKeyCreateDecryptedData(privateKey,
                                                                .eciesEncryptionStandardX963SHA256AESGCM,
                                                                data as CFData,
                                                                &error) else {
                throw error!.takeRetainedValue() as Error
            }
            return decryptedData as Data
        }

}
