//
//  ContentView.swift
//  Vulnerable
//
//  MASTG vulnerable-pattern catalog. EDUCATIONAL ONLY — this app deliberately
//  demonstrates insecure patterns from the OWASP MASTG demos.
//

import SwiftUI

/// All demo groups shown in the catalog.
let demoGroups: [DemoGroup] = [
    DemoGroup(title: "Cryptography", systemImage: "lock.shield", demos: cryptoDemos),
    DemoGroup(title: "Keychain & Biometrics", systemImage: "touchid", demos: keychainBiometricsDemos),
    DemoGroup(title: "Logging & Storage", systemImage: "externaldrive", demos: loggingStorageDemos),
    DemoGroup(title: "Networking & TLS", systemImage: "network", demos: networkingDemos),
    DemoGroup(title: "WebViews", systemImage: "globe", demos: webViewDemos),
    DemoGroup(title: "Platform & Anti-Tampering", systemImage: "link", demos: platformDemos),
    DemoGroup(title: "Text Input", systemImage: "keyboard", demos: textInputDemos),
]

struct ContentView: View {
    /// A deep link received while running; opens the matching URL demo.
    @State private var incomingURL: URL?

    var totalDemos: Int { demoGroups.reduce(0) { $0 + $1.demos.count } }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Label("\(totalDemos) MASTG demos across \(demoGroups.count) categories. For security training only — every entry is intentionally insecure.",
                          systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                }
                ForEach(demoGroups) { group in
                    Section {
                        ForEach(group.demos) { demo in
                            NavigationLink {
                                demo.destination
                            } label: {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(demo.title).font(.body)
                                    Text("\(demo.id) · \(demo.test)")
                                        .font(.caption2.monospaced())
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    } header: {
                        Label(group.title, systemImage: group.systemImage)
                    }
                }
            }
            .navigationTitle("Vulnerable")
            .overlay {
                if let incomingURL {
                    DeepLinkResultView(url: incomingURL) { self.incomingURL = nil }
                }
            }
        }
        // MASTG-DEMO-0134 — custom URL scheme handled with no validation.
        .onOpenURL { url in
            incomingURL = url
        }
        // MASTG-DEMO-0153 — universal link handled with no validation.
        .onContinueUserActivity(NSUserActivityTypeBrowsingWeb) { activity in
            if let url = activity.webpageURL { incomingURL = url }
        }
    }
}

/// Shows how an incoming deep link / universal link is processed with no
/// validation (0134 / 0153 / 0149).
private struct DeepLinkResultView: View {
    let url: URL
    let dismiss: () -> Void

    private var result: String {
        if url.scheme?.hasPrefix("http") == true {
            return PlatformDemos.handleUniversalLink(url)       // 0153
        }
        if url.host == "load" {
            return PlatformDemos.deserializeURLPayload(url)     // 0149
        }
        return PlatformDemos.handleURLWithoutValidation(url)    // 0134
    }

    var body: some View {
        VStack(spacing: 16) {
            Text("Incoming link handled").font(.headline)
            Text(url.absoluteString).font(.caption.monospaced())
            Text(result).font(.footnote).multilineTextAlignment(.center)
            Button("Dismiss", action: dismiss).buttonStyle(.borderedProminent)
        }
        .padding()
        .background(.regularMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 16))
        .padding()
    }
}

#Preview {
    ContentView()
}
