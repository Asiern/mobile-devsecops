//
//  Demo.swift
//  Vulnerable
//
//  Core model for the MASTG vulnerable-pattern catalog.
//
//  EDUCATIONAL USE ONLY. This target deliberately contains insecure code
//  that mirrors the OWASP MASTG demos so the patterns can be practised on
//  with static tools (radare2/rabin2) and dynamic tools (Frida). Do NOT
//  ship any of this. Every demo is tagged with its MASTG-DEMO id.
//

import SwiftUI

/// One catalog entry: a MASTG demo rendered as a vulnerable pattern.
struct Demo: Identifiable {
    /// e.g. "MASTG-DEMO-0011"
    let id: String
    /// Short human title.
    let title: String
    /// The MASTG test this demo exercises, e.g. "MASTG-TEST-0209".
    let test: String
    /// The detail screen that runs / shows the vulnerable pattern.
    let destination: AnyView

    init<V: View>(_ id: String, _ title: String, test: String, @ViewBuilder destination: () -> V) {
        self.id = id
        self.title = title
        self.test = test
        self.destination = AnyView(destination())
    }
}

/// A named group of demos shown as a section in the catalog.
struct DemoGroup: Identifiable {
    let id = UUID()
    let title: String
    let systemImage: String
    let demos: [Demo]
}

/// Generic detail screen for "code-only" demos: shows a description, a button
/// that triggers the vulnerable code, and the textual result.
struct RunnerView: View {
    let demoID: String
    let explanation: String
    let actionTitle: String
    let action: @MainActor () -> String

    @State private var output: String = ""

    init(demoID: String,
         explanation: String,
         actionTitle: String = "Run vulnerable code",
         action: @MainActor @escaping () -> String) {
        self.demoID = demoID
        self.explanation = explanation
        self.actionTitle = actionTitle
        self.action = action
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Label(demoID, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption.bold())
                    .foregroundStyle(.orange)

                Text(explanation)
                    .font(.callout)
                    .foregroundStyle(.secondary)

                Button(actionTitle) {
                    output = action()
                }
                .buttonStyle(.borderedProminent)

                if !output.isEmpty {
                    Text("Output")
                        .font(.headline)
                    Text(output)
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                        .background(.gray.opacity(0.15))
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                }
                Spacer()
            }
            .padding()
        }
        .navigationTitle(demoID)
        .navigationBarTitleDisplayMode(.inline)
    }
}
