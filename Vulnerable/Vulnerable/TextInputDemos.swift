//
//  TextInputDemos.swift
//  Vulnerable
//
//  MASTG text-input demos: keyboard caching and sensitive data not hidden.
//  EDUCATIONAL ONLY.
//

import SwiftUI

// MARK: MASTG-DEMO-0076 / 0077 — Keyboard Caching Not Prevented (MASTG-TEST-0313 / 0314)
/// Sensitive fields that leave autocorrection/keyboard learning ON, so typed
/// secrets get cached by the keyboard.
private struct KeyboardCachingView: View {
    @State private var ssn = ""
    @State private var cardNumber = ""
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Label("MASTG-DEMO-0076", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption.bold()).foregroundStyle(.orange)
                Text("These fields hold sensitive data but do NOT disable autocorrection/keyboard caching, so the keyboard learns and caches the values (also the Frida target 0077).")
                    .font(.footnote).foregroundStyle(.secondary)

                Text("SSN").font(.caption)
                // VULNERABLE: no .autocorrectionDisabled(), default keyboard caching.
                TextField("123-45-6789", text: $ssn)
                    .textFieldStyle(.roundedBorder)

                Text("Card number").font(.caption)
                // VULNERABLE: autocorrection explicitly enabled.
                TextField("4111 1111 1111 1111", text: $cardNumber)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled(false)

                Spacer()
            }
            .padding()
        }
        .navigationTitle("MASTG-DEMO-0076")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: MASTG-DEMO-0112 / 0113 — Text Input Fields Not Hiding Sensitive Data (MASTG-TEST-0346 / 0347)
/// A password entered in a plain TextField (not SecureField) — visible on screen
/// and in screenshots (also the Frida runtime target 0113).
private struct NotHidingSensitiveView: View {
    @State private var password = ""
    @State private var pin = ""
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Label("MASTG-DEMO-0112", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption.bold()).foregroundStyle(.orange)
                Text("Password and PIN entered in plain TextFields instead of SecureField, so the characters are shown on screen and captured in screenshots.")
                    .font(.footnote).foregroundStyle(.secondary)

                Text("Password").font(.caption)
                // VULNERABLE: should be SecureField.
                TextField("password", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .textInputAutocapitalization(.never)

                Text("PIN").font(.caption)
                TextField("PIN", text: $pin)           // VULNERABLE: visible PIN
                    .textFieldStyle(.roundedBorder)
                    .keyboardType(.numberPad)

                if !password.isEmpty {
                    Text("Currently visible on screen: \(password)")
                        .font(.footnote).foregroundStyle(.red)
                }
                Spacer()
            }
            .padding()
        }
        .navigationTitle("MASTG-DEMO-0112")
        .navigationBarTitleDisplayMode(.inline)
    }
}

let textInputDemos: [Demo] = [
    Demo("MASTG-DEMO-0076", "Keyboard caching not prevented", test: "MASTG-TEST-0313") {
        KeyboardCachingView()
    },
    Demo("MASTG-DEMO-0112", "Sensitive data not hidden", test: "MASTG-TEST-0346") {
        NotHidingSensitiveView()
    },
]
