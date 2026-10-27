//
//  CryptoDemos.swift
//  Vulnerable
//
//  MASTG cryptography demos. EDUCATIONAL ONLY — every function here is a
//  deliberate anti-pattern.
//

import Foundation
import Security
import CommonCrypto
import CryptoKit
import SwiftUI

enum CryptoDemos {

    // MARK: MASTG-DEMO-0011 — Insufficient Key Size in SecKeyCreateRandomKey (MASTG-TEST-0209)
    /// Generates an RSA key pair with a 512-bit modulus. Key sizes below 2048
    /// bits are considered broken for RSA.
    static func insufficientKeySize() -> String {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 512, // VULNERABLE: far below the 2048-bit minimum
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            return "Key generation failed: \(error!.takeRetainedValue())"
        }
        let bits = SecKeyGetBlockSize(key) * 8
        return "Generated RSA key with \(bits)-bit modulus (insecure: < 2048 bits)."
    }

    // MARK: MASTG-DEMO-0013 — Hardcoded RSA Private Key in SecKeyCreateWithData (MASTG-TEST-0213)
    /// A private key embedded in the binary. Anyone can extract it with `strings`
    /// / rabin2 and impersonate the app.
    static let hardcodedRSAPrivateKeyPEM = """
    -----BEGIN RSA PRIVATE KEY-----
    MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
    KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
    o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
    TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp79
    mxDXDf6zYdQAJt6p4YJ2Z6qO2GOQ0CIQCPsfTL1QGZ8SjVNHdfJ1FHH4jR6tTV2L
    Xc5A2QqdAiEBvJ8l7Z5FN2hzB4oY2Y3b4lQe3xWkKQ6s8m5qQ0AiEA3+dQW9GQXb
    zR1Jq3Xz6g7p1y0b3N5e0u5y8x2w9lT0=
    -----END RSA PRIVATE KEY-----
    """

    static func hardcodedRSAPrivateKey() -> String {
        // The secret is a compile-time string literal, i.e. baked into __TEXT.
        let der = Data(base64Encoded:
            "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu" +
            "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==") ?? Data()
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        ]
        var error: Unmanaged<CFError>?
        _ = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, &error)
        return "Loaded a hardcoded RSA private key embedded in the binary:\n\n\(hardcodedRSAPrivateKeyPEM)"
    }

    // MARK: MASTG-DEMO-0014 — Hardcoded ECDSA Private Key in CryptoKit (MASTG-TEST-0213)
    /// A P-256 signing key whose raw representation is hardcoded.
    static let hardcodedECDSAKeyHex =
        "a1b2c3d4e5f6071829304152637485960718293041526374859607182930a1b2"

    static func hardcodedECDSAPrivateKey() -> String {
        guard let raw = Data(hex: hardcodedECDSAKeyHex) else { return "bad key" }
        do {
            let key = try P256.Signing.PrivateKey(rawRepresentation: raw) // VULNERABLE: static key material
            let sig = try key.signature(for: Data("message".utf8))
            return "Signed with hardcoded ECDSA P-256 key.\nKey (hex): \(hardcodedECDSAKeyHex)\nSignature: \(sig.rawRepresentation.prefix(8).hexString)…"
        } catch {
            return "error: \(error)"
        }
    }

    // MARK: MASTG-DEMO-0015 — Broken Hashing in CommonCrypto (MASTG-TEST-0211)
    /// MD5 and SHA-1 via CommonCrypto. Both are collision-broken.
    static func brokenHashingCommonCrypto() -> String {
        let data = Data("sensitive-password".utf8)

        var md5 = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        _ = data.withUnsafeBytes { CC_MD5($0.baseAddress, CC_LONG(data.count), &md5) }

        var sha1 = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        _ = data.withUnsafeBytes { CC_SHA1($0.baseAddress, CC_LONG(data.count), &sha1) }

        return "MD5:  \(md5.hexString)\nSHA1: \(sha1.hexString)\n(both broken)"
    }

    // MARK: MASTG-DEMO-0016 — Broken Hashing in CryptoKit (MASTG-TEST-0211)
    static func brokenHashingCryptoKit() -> String {
        let data = Data("sensitive-password".utf8)
        let md5 = Insecure.MD5.hash(data: data)   // VULNERABLE
        let sha1 = Insecure.SHA1.hash(data: data)  // VULNERABLE
        return "Insecure.MD5:  \(md5.map { String(format: "%02x", $0) }.joined())\n" +
               "Insecure.SHA1: \(sha1.map { String(format: "%02x", $0) }.joined())"
    }

    // MARK: MASTG-DEMO-0018 — Broken Encryption Algorithm in CommonCrypto (MASTG-TEST-0210)
    /// DES — a 56-bit cipher that is trivially brute-forced today.
    static func brokenEncryptionDES() -> String {
        let key = "8bytekey".data(using: .utf8)!            // DES key = 8 bytes
        let plaintext = "top secret".data(using: .utf8)!
        var out = [UInt8](repeating: 0, count: plaintext.count + kCCBlockSizeDES)
        var moved = 0
        let status = key.withUnsafeBytes { keyPtr in
            plaintext.withUnsafeBytes { dataPtr in
                CCCrypt(CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmDES),           // VULNERABLE: DES
                        CCOptions(kCCOptionECBMode | kCCOptionPKCS7Padding),
                        keyPtr.baseAddress, key.count,
                        nil,
                        dataPtr.baseAddress, plaintext.count,
                        &out, out.count, &moved)
            }
        }
        return "CCCrypt(kCCAlgorithmDES) status=\(status)\nciphertext: \(Array(out.prefix(moved)).hexString)"
    }

    // MARK: MASTG-DEMO-0080 — Broken Encryption Mode in CommonCrypto (MASTG-TEST-0317)
    /// AES in ECB mode: identical plaintext blocks map to identical ciphertext
    /// blocks, leaking structure (the "ECB penguin").
    static func brokenEncryptionModeECB() -> String {
        let key = "0123456789abcdef".data(using: .utf8)!     // 128-bit AES key
        let plaintext = Data(repeating: 0x41, count: 32)     // two identical blocks
        var out = [UInt8](repeating: 0, count: plaintext.count + kCCBlockSizeAES128)
        var moved = 0
        _ = key.withUnsafeBytes { keyPtr in
            plaintext.withUnsafeBytes { dataPtr in
                CCCrypt(CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode | kCCOptionPKCS7Padding), // VULNERABLE: ECB
                        keyPtr.baseAddress, key.count,
                        nil,
                        dataPtr.baseAddress, plaintext.count,
                        &out, out.count, &moved)
            }
        }
        let ct = Array(out.prefix(moved))
        let block1 = ct.prefix(16).hexString
        let block2 = ct.dropFirst(16).prefix(16).hexString
        return "AES-ECB ciphertext of two identical plaintext blocks:\nblock1: \(block1)\nblock2: \(block2)\n(identical blocks leak via ECB)"
    }

    // MARK: MASTG-DEMO-0117 — Sensitive Data through CCCrypt (MASTG-TEST-0354)
    /// A plain CCCrypt AES call whose key/IV/plaintext are observable by hooking
    /// CCCrypt at runtime with Frida.
    static func cccryptSensitiveData() -> String {
        let key = "ThisIsASecretKey".data(using: .utf8)!     // 16 bytes
        let iv = "InitializationVe".data(using: .utf8)!       // 16 bytes
        let plaintext = "Cardholder:4111111111111111".data(using: .utf8)!
        var out = [UInt8](repeating: 0, count: plaintext.count + kCCBlockSizeAES128)
        var moved = 0
        _ = key.withUnsafeBytes { keyPtr in
            iv.withUnsafeBytes { ivPtr in
                plaintext.withUnsafeBytes { dataPtr in
                    CCCrypt(CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyPtr.baseAddress, key.count,
                            ivPtr.baseAddress,
                            dataPtr.baseAddress, plaintext.count,
                            &out, out.count, &moved)
                }
            }
        }
        return "Encrypted PAN via CCCrypt. Key/IV/plaintext are visible to a Frida hook on CCCrypt.\nciphertext: \(Array(out.prefix(moved)).hexString)"
    }
}

// MARK: - Hex helpers

extension Sequence where Element == UInt8 {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}

extension Data {
    init?(hex: String) {
        guard hex.count % 2 == 0 else { return nil }
        var data = Data(capacity: hex.count / 2)
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            guard let b = UInt8(hex[idx..<next], radix: 16) else { return nil }
            data.append(b)
            idx = next
        }
        self = data
    }
}

let cryptoDemos: [Demo] = [
    Demo("MASTG-DEMO-0011", "Insufficient RSA key size", test: "MASTG-TEST-0209") {
        RunnerView(demoID: "MASTG-DEMO-0011",
                   explanation: "SecKeyCreateRandomKey generates an RSA key with only a 512-bit modulus — well below the 2048-bit minimum.",
                   action: CryptoDemos.insufficientKeySize)
    },
    Demo("MASTG-DEMO-0013", "Hardcoded RSA private key", test: "MASTG-TEST-0213") {
        RunnerView(demoID: "MASTG-DEMO-0013",
                   explanation: "A PEM/DER RSA private key is embedded in the binary and loaded with SecKeyCreateWithData. Extractable with strings/rabin2.",
                   action: CryptoDemos.hardcodedRSAPrivateKey)
    },
    Demo("MASTG-DEMO-0014", "Hardcoded ECDSA private key", test: "MASTG-TEST-0213") {
        RunnerView(demoID: "MASTG-DEMO-0014",
                   explanation: "A CryptoKit P256.Signing.PrivateKey built from a hardcoded raw representation.",
                   action: CryptoDemos.hardcodedECDSAPrivateKey)
    },
    Demo("MASTG-DEMO-0015", "Broken hashing (CommonCrypto)", test: "MASTG-TEST-0211") {
        RunnerView(demoID: "MASTG-DEMO-0015",
                   explanation: "MD5 and SHA-1 computed via CC_MD5 / CC_SHA1. Both are collision-broken.",
                   action: CryptoDemos.brokenHashingCommonCrypto)
    },
    Demo("MASTG-DEMO-0016", "Broken hashing (CryptoKit)", test: "MASTG-TEST-0211") {
        RunnerView(demoID: "MASTG-DEMO-0016",
                   explanation: "Insecure.MD5 / Insecure.SHA1 from CryptoKit.",
                   action: CryptoDemos.brokenHashingCryptoKit)
    },
    Demo("MASTG-DEMO-0018", "Broken encryption (DES)", test: "MASTG-TEST-0210") {
        RunnerView(demoID: "MASTG-DEMO-0018",
                   explanation: "CCCrypt invoked with kCCAlgorithmDES — a 56-bit cipher.",
                   action: CryptoDemos.brokenEncryptionDES)
    },
    Demo("MASTG-DEMO-0080", "Broken encryption mode (ECB)", test: "MASTG-TEST-0317") {
        RunnerView(demoID: "MASTG-DEMO-0080",
                   explanation: "AES used in ECB mode (kCCOptionECBMode): identical plaintext blocks produce identical ciphertext blocks.",
                   action: CryptoDemos.brokenEncryptionModeECB)
    },
    Demo("MASTG-DEMO-0117", "Sensitive data via CCCrypt", test: "MASTG-TEST-0354") {
        RunnerView(demoID: "MASTG-DEMO-0117",
                   explanation: "A CCCrypt AES call whose key, IV and plaintext (a PAN) can be lifted by hooking CCCrypt with Frida.",
                   action: CryptoDemos.cccryptSensitiveData)
    },
]
