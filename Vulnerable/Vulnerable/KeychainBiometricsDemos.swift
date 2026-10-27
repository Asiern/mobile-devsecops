//
//  KeychainBiometricsDemos.swift
//  Vulnerable
//
//  MASTG keychain-access-control and local-authentication demos.
//  EDUCATIONAL ONLY.
//

import Foundation
import Security
import LocalAuthentication
import SwiftUI

enum KeychainBiometricsDemos {

    private static let service = "asiern.Vulnerable.demo"

    // MARK: MASTG-DEMO-0024 / 0026 — LAContext.canEvaluatePolicy (MASTG-TEST-0248 / 0246)
    /// Only *checks* whether biometrics are available. canEvaluatePolicy performs
    /// no authentication and is trivially bypassed by a Frida hook forcing `true`.
    static func canEvaluatePolicy() -> String {
        let context = LAContext()
        var error: NSError?
        let ok = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        return "canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics) = \(ok)\n" +
               (error.map { "error: \($0.localizedDescription)" } ?? "no error") +
               "\n\nNote: this only probes availability; a Frida hook can force the return value to true."
    }

    // MARK: MASTG-DEMO-0041 / 0042 — LAContext.evaluatePolicy (MASTG-TEST-0266 / 0267)
    /// Gates access purely on the boolean result of evaluatePolicy, with no
    /// keychain binding. A Frida hook on the completion handler bypasses it.
    static func evaluatePolicy(completion: @escaping (String) -> Void) {
        let context = LAContext()
        let reason = "Authenticate to view your secret"
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
            // VULNERABLE: the secret is released based only on this boolean.
            if success {
                completion("Authentication succeeded — secret unlocked: s3cr3t-token")
            } else {
                completion("Authentication failed: \(error?.localizedDescription ?? "unknown")")
            }
        }
    }

    // MARK: MASTG-DEMO-0043 / 0044 — kSecAccessControlUserPresence (MASTG-TEST-0268 / 0269)
    /// Stores an item protected by `.userPresence`. Accepts device passcode as a
    /// fallback and the ACL can be stripped at runtime with Frida.
    static func storeWithUserPresence() -> String {
        delete(account: "userPresence")
        guard let acl = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            .userPresence, nil) else {
            return "failed to build access control"
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "userPresence",
            kSecValueData as String: Data("secret-userPresence".utf8),
            kSecAttrAccessControl as String: acl,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        return "SecItemAdd with .userPresence → OSStatus \(status)\n(.userPresence allows passcode fallback)."
    }

    // MARK: MASTG-DEMO-0045 / 0046 — kSecAccessControlBiometryCurrentSet (MASTG-TEST-0270 / 0271)
    static func storeWithBiometryCurrentSet() -> String {
        delete(account: "biometryCurrentSet")
        guard let acl = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            .biometryCurrentSet, nil) else {
            return "failed to build access control"
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "biometryCurrentSet",
            kSecValueData as String: Data("secret-biometryCurrentSet".utf8),
            kSecAttrAccessControl as String: acl,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        return "SecItemAdd with .biometryCurrentSet → OSStatus \(status)"
    }

    // MARK: MASTG-DEMO-0047 — Keychain Not Requiring User Presence (MASTG-TEST-0266)
    /// Stores a "secret" with NO access-control flags and the weakest practical
    /// accessibility (`kSecAttrAccessibleAlways`-style). It can be read with no
    /// user presence whatsoever.
    static func storeWithoutUserPresence() -> String {
        delete(account: "noPresence")
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "noPresence",
            kSecValueData as String: Data("secret-no-presence-required".utf8),
            // VULNERABLE: readable after first unlock, no biometrics/passcode gate.
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        let value = read(account: "noPresence")
        return "Stored without user presence → OSStatus \(status)\nImmediately read back: \(value ?? "nil")"
    }

    // MARK: helpers
    private static func read(account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func delete(account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
    }
}

/// Detail view for the async evaluatePolicy demos (0041/0042).
struct EvaluatePolicyView: View {
    @State private var output = ""
    var body: some View {
        RunnerView(demoID: "MASTG-DEMO-0041",
                   explanation: "LAContext.evaluatePolicy releases a secret based only on the success boolean — no keychain binding. A Frida hook on the completion block bypasses it.",
                   actionTitle: "Authenticate") {
            KeychainBiometricsDemos.evaluatePolicy { result in
                DispatchQueue.main.async { output = result }
            }
            return output.isEmpty ? "Prompting for authentication…" : output
        }
    }
}

let keychainBiometricsDemos: [Demo] = [
    Demo("MASTG-DEMO-0024", "LAContext.canEvaluatePolicy", test: "MASTG-TEST-0248") {
        RunnerView(demoID: "MASTG-DEMO-0024",
                   explanation: "canEvaluatePolicy only checks availability and performs no authentication (also the target of the Frida demo 0026).",
                   action: KeychainBiometricsDemos.canEvaluatePolicy)
    },
    Demo("MASTG-DEMO-0041", "LAContext.evaluatePolicy", test: "MASTG-TEST-0266") {
        EvaluatePolicyView()
    },
    Demo("MASTG-DEMO-0043", "kSecAccessControlUserPresence", test: "MASTG-TEST-0268") {
        RunnerView(demoID: "MASTG-DEMO-0043",
                   explanation: "Keychain item protected with .userPresence, which permits a device-passcode fallback (also the Frida target in 0044).",
                   action: KeychainBiometricsDemos.storeWithUserPresence)
    },
    Demo("MASTG-DEMO-0045", "kSecAccessControlBiometryCurrentSet", test: "MASTG-TEST-0270") {
        RunnerView(demoID: "MASTG-DEMO-0045",
                   explanation: "Keychain item protected with .biometryCurrentSet (also the Frida target in 0046).",
                   action: KeychainBiometricsDemos.storeWithBiometryCurrentSet)
    },
    Demo("MASTG-DEMO-0047", "Keychain without user presence", test: "MASTG-TEST-0266") {
        RunnerView(demoID: "MASTG-DEMO-0047",
                   explanation: "A secret stored with no access-control flags and kSecAttrAccessibleAfterFirstUnlock — readable with no user presence.",
                   action: KeychainBiometricsDemos.storeWithoutUserPresence)
    },
]
