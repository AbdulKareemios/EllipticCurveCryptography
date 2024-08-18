//
//  ContentView.swift
//  EllipticCurveCryptography
//
//  Created by Abdul Kareem on 8/18/24.
//

import SwiftUI

import CryptoKit
struct ContentView: View {
    
    private let eccManager = ECCManager(tag: "com.abdulkareem.mykey")
    
    @State private var signature: Data?
    @State private var isVerified: Bool?
    @State private var responseMessage: String?
    
    
    var body: some View {
        VStack(spacing: 20) {
            
            Button("Generate Key Pair") {
                do {
                    try eccManager.generateKeyPair()
                    responseMessage = "Key pair generated successfully."
                } catch {
                    responseMessage = "Failed to generate key pair: \(error.localizedDescription)"
                }
            }
            
            Button("Sign and Verify Message") {
                do {
                    let message = "Hello, this is my secret message"
                    let messageData = message.data(using: .utf8)!
                    
                    // Hash the message
                    let messageHash = SHA256.hash(data: messageData)
                    
                    let messageHashData = Data(messageHash)
                    // Sign the message hash
                    guard let signature = try eccManager.sign(data: messageHashData) else {
                        responseMessage = "Signing failed"
                        return
                    }
                    
                    self.signature = signature
                    
                    // Verify the signature with the message hash
                    let isVerified = try eccManager.verify(data: messageHashData, signature: signature)
                    self.isVerified = isVerified
                    
                    if !isVerified {
                        responseMessage = "Verification failed"
                    } else {
                        responseMessage = "Message signed and verified successfully."
                    }
                } catch {
                    responseMessage = "Signing/Verification failed: \(error.localizedDescription)"
                }
            }
            if let signature = signature {
                Text("Signature: \(signature.base64EncodedString())")
                    .padding()
            }
            
            if let isVerified = isVerified {
                Text("Verification: \(isVerified ? "Success" : "Failed")")
                    .foregroundColor(isVerified ? .green : .red)
                    .padding()
            }

            if let errorMessage = responseMessage {
                
                Text("\(errorMessage)")
                    .foregroundColor(.gray)
                    .padding()
                
                
            }
        }
        .padding()
    }
}
#Preview {
    ContentView()
}
