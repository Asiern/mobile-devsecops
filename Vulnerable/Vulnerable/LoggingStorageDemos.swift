//
//  LoggingStorageDemos.swift
//  Vulnerable
//
//  MASTG logging, local-storage, backup and insecure-randomness demos.
//  EDUCATIONAL ONLY.
//

import Foundation
import os
import SwiftUI

enum LoggingStorageDemos {

    private static let logger = Logger(subsystem: "asiern.Vulnerable", category: "demo")

    // MARK: MASTG-DEMO-0065 — Uses of Logging APIs (MASTG-TEST-0297)
    // MARK: MASTG-DEMO-0066 — Sensitive Data Logging (MASTG-TEST-0296)
    /// Logs sensitive data via os.Logger / NSLog / print. The `.public` privacy
    /// marker forces the value into the device log in cleartext (idevicesyslog).
    static func logSensitiveData() -> String {
        let password = "hunter2"
        let token = "eyJhbGciOiJIUzI1NiJ9.fake.jwt"
        logger.log("User password: \(password, privacy: .public)")        // VULNERABLE
        logger.error("Auth token: \(token, privacy: .public)")            // VULNERABLE
        NSLog("NSLog password=%@ token=%@", password, token)              // VULNERABLE
        print("print() password=\(password)")                            // VULNERABLE
        return "Logged password and auth token in cleartext via Logger/NSLog/print.\nVisible with idevicesyslog / Console.app."
    }

    // MARK: MASTG-DEMO-0124 — Logging Exposing Implementation Details (MASTG-TEST-0358)
    // MASTG-DEMO-0125 — Implementation Details Exposed in App Logs (MASTG-TEST-0359)
    /// Leaks internal implementation details (endpoints, SQL, file paths, flags).
    static func logImplementationDetails() -> String {
        logger.debug("SQL: SELECT * FROM users WHERE id = 42 AND admin = 1")
        logger.log("Calling internal endpoint https://internal.api.corp/v2/debug?feature=beta")
        logger.log("Decryption routine useLegacyAES=\(true, privacy: .public) keyDerivation=PBKDF2-1000")
        logger.log("Caching dir: \(NSHomeDirectory(), privacy: .public)/Library/Caches/secrets.db")
        return "Logged internal SQL, endpoints, feature flags and file paths — handy map for an attacker."
    }

    // MARK: MASTG-DEMO-0019 — Uses of isExcludedFromBackupKey (MASTG-TEST-0215)
    /// Writes a file and clears its "excluded from backup" flag (default is
    /// already included, but this makes it explicit), so secrets land in
    /// iCloud/iTunes backups.
    static func writeFileIncludedInBackup() -> String {
        let url = FileManager.default
            .urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("secrets.txt")
        try? Data("api_key=AKIA-SECRET-EXAMPLE".utf8).write(to: url)
        var values = URLResourceValues()
        values.isExcludedFromBackup = false        // VULNERABLE: secret will be backed up
        var mutable = url
        try? mutable.setResourceValues(values)
        return "Wrote secrets.txt and set isExcludedFromBackup = false → included in backups.\n\(url.path)"
    }

    // MARK: MASTG-DEMO-0067 — Files Eligible for Backup (MASTG-TEST-0298)
    /// Writes a sensitive file with no file-protection and leaves it eligible
    /// for backup (target of the Frida backup-tracking demo).
    static func writeBackupEligibleFile() -> String {
        let url = FileManager.default
            .urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("session.json")
        let body = #"{"session":"abc123","pan":"4111111111111111"}"#
        // .noFileProtection: readable even when the device is locked.
        try? body.data(using: .utf8)?.write(to: url, options: [.noFileProtection])
        return "Wrote session.json with .noFileProtection in Documents/ (backed up by default)."
    }

    // MARK: MASTG-DEMO-0150 — Storage Integrity Check APIs (MASTG-TEST-0387)
    /// Persists a value in UserDefaults with no integrity protection (no MAC /
    /// signature), so it can be tampered with on a jailbroken device.
    static func storeWithoutIntegrityCheck() -> String {
        let defaults = UserDefaults.standard
        defaults.set(false, forKey: "isPremiumUser")       // attacker flips to true
        defaults.set(0, forKey: "accountBalance")          // attacker edits freely
        defaults.synchronize()
        return "Stored isPremiumUser/accountBalance in UserDefaults with no integrity check (MAC/signature). Editable in the plist on a jailbroken device."
    }

    // MARK: MASTG-DEMO-0073 / 0074 — Insecure Random Number Generation (MASTG-TEST-0311 / 0349)
    /// Uses non-cryptographic PRNGs (arc4random, rand, random, drand48) to build
    /// a "security token".
    static func insecureRandom() -> String {
        let a = arc4random()                               // VULNERABLE
        let b = arc4random_uniform(1_000_000)              // VULNERABLE
        srand48(Int(Date().timeIntervalSince1970))
        let c = drand48()                                  // VULNERABLE (seeded with time)
        // VULNERABLE: a hand-rolled linear congruential generator seeded with time.
        var state = UInt64(truncatingIfNeeded: time(nil))
        state = 6364136223846793005 &* state &+ 1442695040888963407
        let d = UInt32(truncatingIfNeeded: state >> 33)
        let token = String(format: "%08x%06u", a, b)
        return "Insecure 'security token' from non-crypto PRNGs:\narc4random=\(a)\narc4random_uniform=\(b)\ndrand48=\(c)\ncustom LCG=\(d)\ntoken=\(token)\nUse SecRandomCopyBytes instead."
    }
}

let loggingStorageDemos: [Demo] = [
    Demo("MASTG-DEMO-0065", "Logging APIs", test: "MASTG-TEST-0297") {
        RunnerView(demoID: "MASTG-DEMO-0065",
                   explanation: "Sensitive values logged via os.Logger/NSLog/print with .public privacy (covers 0066's idevicesyslog capture too).",
                   action: LoggingStorageDemos.logSensitiveData)
    },
    Demo("MASTG-DEMO-0124", "Logging implementation details", test: "MASTG-TEST-0358") {
        RunnerView(demoID: "MASTG-DEMO-0124",
                   explanation: "Internal SQL, endpoints, feature flags and paths written to the log (covers 0125).",
                   action: LoggingStorageDemos.logImplementationDetails)
    },
    Demo("MASTG-DEMO-0019", "isExcludedFromBackupKey = false", test: "MASTG-TEST-0215") {
        RunnerView(demoID: "MASTG-DEMO-0019",
                   explanation: "A secret file explicitly marked isExcludedFromBackup = false, so it is copied into backups.",
                   action: LoggingStorageDemos.writeFileIncludedInBackup)
    },
    Demo("MASTG-DEMO-0067", "File eligible for backup", test: "MASTG-TEST-0298") {
        RunnerView(demoID: "MASTG-DEMO-0067",
                   explanation: "A sensitive file written with .noFileProtection, eligible for backup (Frida backup-tracking target).",
                   action: LoggingStorageDemos.writeBackupEligibleFile)
    },
    Demo("MASTG-DEMO-0150", "Storage without integrity check", test: "MASTG-TEST-0387") {
        RunnerView(demoID: "MASTG-DEMO-0150",
                   explanation: "Security-relevant flags stored in UserDefaults with no integrity protection.",
                   action: LoggingStorageDemos.storeWithoutIntegrityCheck)
    },
    Demo("MASTG-DEMO-0073", "Insecure random generation", test: "MASTG-TEST-0311") {
        RunnerView(demoID: "MASTG-DEMO-0073",
                   explanation: "Security token built from arc4random/rand/random/drand48 (covers the frida-trace demo 0074).",
                   action: LoggingStorageDemos.insecureRandom)
    },
]
