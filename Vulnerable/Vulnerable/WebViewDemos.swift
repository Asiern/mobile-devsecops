//
//  WebViewDemos.swift
//  Vulnerable
//
//  MASTG WebView demos. EDUCATIONAL ONLY.
//

import SwiftUI
import WebKit

// MARK: - WKWebView wrapper

/// A deliberately mis-configured WKWebView used by several demos.
struct VulnerableWebView: UIViewRepresentable {
    enum Mode {
        case remote(urlString: String)                // 0095
        case html(String, baseURL: URL?)              // 0096
        case localFile                                 // 0098 / 0099
        case nativeBridge                              // 0142
        case bridgeReturnsSecret                       // 0143
        case passwordInDOM                             // 0144
        case domInspection                             // 0145
        case writeSecretToDOM                          // 0146
    }

    let mode: Mode
    var onEvent: (String) -> Void = { _ in }

    func makeCoordinator() -> Coordinator { Coordinator(onEvent: onEvent) }

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()

        // MASTG-DEMO-0098 / 0099 — enable file access from file URLs (private prefs).
        // These are exactly the references radare2/Frida look for.
        config.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")      // VULNERABLE
        config.setValue(true, forKey: "allowUniversalAccessFromFileURLs")             // VULNERABLE

        switch mode {
        case .nativeBridge, .bridgeReturnsSecret:
            // MASTG-DEMO-0142 / 0143 — expose a native message handler to page JS
            // in the PAGE content world (no isolation).
            config.userContentController.add(context.coordinator, name: "nativeBridge")
        case .domInspection:
            // MASTG-DEMO-0145 — handler added without a separate content world.
            config.userContentController.add(context.coordinator, name: "domInspect")
        default:
            break
        }

        let webView = WKWebView(frame: .zero, configuration: config)
        context.coordinator.webView = webView
        load(into: webView, context: context)
        return webView
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {}

    private func load(into webView: WKWebView, context: Context) {
        switch mode {
        case .remote(let urlString):
            // MASTG-DEMO-0095 — load attacker-controllable URL with no validation.
            if let url = URL(string: urlString) {
                webView.load(URLRequest(url: url))           // VULNERABLE: no scheme/host allow-list
            }

        case .html(let html, let baseURL):
            // MASTG-DEMO-0096 — render attacker-influenced HTML with a file base URL.
            let fileBase = baseURL ?? URL(fileURLWithPath: NSHomeDirectory())
            webView.loadHTMLString(html, baseURL: fileBase)  // VULNERABLE

        case .localFile:
            // MASTG-DEMO-0098 / 0099 — grant read access to the whole home dir.
            let home = URL(fileURLWithPath: NSHomeDirectory())
            let index = writeLocalPage()
            webView.loadFileURL(index, allowingReadAccessTo: home)  // VULNERABLE: broad read scope

        case .nativeBridge:
            webView.loadHTMLString(Self.bridgePage, baseURL: nil)

        case .bridgeReturnsSecret:
            webView.loadHTMLString(Self.bridgeReturnPage, baseURL: nil)

        case .passwordInDOM:
            // MASTG-DEMO-0144 — a password field living in the WebView DOM.
            webView.loadHTMLString(Self.passwordPage, baseURL: nil)

        case .domInspection:
            webView.loadHTMLString(Self.domInspectPage, baseURL: nil)
            // MASTG-DEMO-0145 — read the DOM in the default (page) content world.
            webView.evaluateJavaScript("document.body.innerHTML") { value, _ in
                context.coordinator.onEvent("DOM read (no content-world isolation): \(String(describing: value).prefix(120))…")
            }

        case .writeSecretToDOM:
            webView.loadHTMLString(Self.sinkPage, baseURL: nil)
            // MASTG-DEMO-0146 — inject a secret straight into the page DOM.
            let secret = "sessionToken=eyJ.fake.jwt; pan=4111111111111111"
            webView.evaluateJavaScript("document.getElementById('sink').innerText = '\(secret)';") { _, _ in
                context.coordinator.onEvent("Wrote secret into page DOM via evaluateJavaScript — now readable by page JS.")
            }
        }
    }

    /// Writes a tiny HTML file that tries to read a local file via XHR (0096/0098).
    private func writeLocalPage() -> URL {
        let dir = FileManager.default.temporaryDirectory
        let secret = dir.appendingPathComponent("local_secret.txt")
        try? "LOCAL-FILE-SECRET-1234".data(using: .utf8)?.write(to: secret)
        let index = dir.appendingPathComponent("index.html")
        let html = """
        <html><body><h3>Local page</h3><pre id='out'></pre>
        <script>
          // With file access enabled, this reads a sibling local file.
          fetch('local_secret.txt').then(r=>r.text())
            .then(t=>{document.getElementById('out').innerText='leaked: '+t;})
            .catch(e=>{document.getElementById('out').innerText='err: '+e;});
        </script></body></html>
        """
        try? html.data(using: .utf8)?.write(to: index)
        return index
    }

    // MARK: Pages
    static let bridgePage = """
    <html><body><h3>Native bridge</h3><button onclick="call()">Get user data</button>
    <pre id='o'></pre>
    <script>
      function call(){ window.webkit.messageHandlers.nativeBridge.postMessage({cmd:'getUser'}); }
      function deliver(d){ document.getElementById('o').innerText = JSON.stringify(d); }
    </script></body></html>
    """

    static let bridgeReturnPage = """
    <html><body><h3>Bridge → evaluateJavaScript</h3>
    <button onclick="window.webkit.messageHandlers.nativeBridge.postMessage('token')">Request token</button>
    <pre id='o'></pre></body></html>
    """

    static let passwordPage = """
    <html><body><h3>Login</h3>
    <form><input id='u' placeholder='username'><br>
    <input id='p' type='password' placeholder='password'></form>
    <p>Password typed here lives in the WebView DOM — no native secure overlay.</p>
    </body></html>
    """

    static let domInspectPage = """
    <html><body><div id='secret'>card: 4111 1111 1111 1111</div></body></html>
    """

    static let sinkPage = """
    <html><body><h3>Sink</h3><div id='sink'>(empty)</div></body></html>
    """

    // MARK: Coordinator (native side of the bridge)
    final class Coordinator: NSObject, WKScriptMessageHandler {
        var webView: WKWebView?
        let onEvent: (String) -> Void
        init(onEvent: @escaping (String) -> Void) { self.onEvent = onEvent }

        func userContentController(_ userContentController: WKUserContentController,
                                   didReceive message: WKScriptMessage) {
            // MASTG-DEMO-0142 — hand sensitive native data straight to page JS.
            let secrets: [String: Any] = [
                "email": "victim@example.com",
                "authToken": "eyJhbGciOiJIUzI1NiJ9.fake.jwt",
                "balance": 48230,
            ]
            if message.name == "nativeBridge" {
                if let json = try? JSONSerialization.data(withJSONObject: secrets),
                   let s = String(data: json, encoding: .utf8) {
                    // MASTG-DEMO-0143 — push the secret back into the page via evaluateJavaScript.
                    webView?.evaluateJavaScript("deliver(\(s))", completionHandler: nil)
                    onEvent("Native bridge returned secrets to page JS: \(s)")
                }
            } else if message.name == "domInspect" {
                onEvent("domInspect message: \(message.body)")
            }
        }
    }
}

// MARK: - Demo detail views

private struct WebDemoScreen: View {
    let demoID: String
    let explanation: String
    let mode: VulnerableWebView.Mode
    @State private var event = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(demoID, systemImage: "exclamationmark.triangle.fill")
                .font(.caption.bold()).foregroundStyle(.orange).padding(.horizontal)
            Text(explanation).font(.footnote).foregroundStyle(.secondary).padding(.horizontal)
            VulnerableWebView(mode: mode) { event = $0 }
                .border(.gray.opacity(0.3))
            if !event.isEmpty {
                Text(event).font(.system(.caption2, design: .monospaced))
                    .padding(.horizontal).padding(.bottom, 4)
            }
        }
        .navigationTitle(demoID)
        .navigationBarTitleDisplayMode(.inline)
    }
}

/// MASTG-DEMO-0095 — user types a URL that is loaded with no validation.
private struct AttackerURLScreen: View {
    @State private var urlString = "http://example.com"
    @State private var loaded: String? = nil
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("MASTG-DEMO-0095", systemImage: "exclamationmark.triangle.fill")
                .font(.caption.bold()).foregroundStyle(.orange)
            Text("The entered string is loaded into WKWebView with no scheme/host validation.")
                .font(.footnote).foregroundStyle(.secondary)
            HStack {
                TextField("URL", text: $urlString).textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled().textInputAutocapitalization(.never)
                Button("Load") { loaded = urlString }
            }
            if let loaded {
                VulnerableWebView(mode: .remote(urlString: loaded)).border(.gray.opacity(0.3))
            } else {
                Spacer()
            }
        }
        .padding([.horizontal, .top])
        .navigationTitle("MASTG-DEMO-0095")
        .navigationBarTitleDisplayMode(.inline)
    }
}

/// MASTG-DEMO-0096 — attacker-influenced text is interpolated into local HTML.
private struct HTMLInjectionScreen: View {
    @State private var name = "<img src=x onerror=\"fetch('file:///etc/passwd')\">"
    @State private var html: String? = nil
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("MASTG-DEMO-0096", systemImage: "exclamationmark.triangle.fill")
                .font(.caption.bold()).foregroundStyle(.orange)
            Text("User input is concatenated into HTML and rendered with a file:// base URL and file access enabled.")
                .font(.footnote).foregroundStyle(.secondary)
            TextField("name", text: $name, axis: .vertical).textFieldStyle(.roundedBorder)
            Button("Render") {
                html = "<html><body><h3>Hello \(name)</h3></body></html>" // VULNERABLE: no escaping
            }
            if let html {
                VulnerableWebView(mode: .html(html, baseURL: URL(fileURLWithPath: NSHomeDirectory())))
                    .border(.gray.opacity(0.3))
            } else { Spacer() }
        }
        .padding([.horizontal, .top])
        .navigationTitle("MASTG-DEMO-0096")
        .navigationBarTitleDisplayMode(.inline)
    }
}

let webViewDemos: [Demo] = [
    Demo("MASTG-DEMO-0094", "Deprecated UIWebView reference", test: "MASTG-TEST-0331") {
        RunnerView(demoID: "MASTG-DEMO-0094",
                   explanation: "Leaves a reference to the removed/deprecated UIWebView class in the binary (what radare2 detects).") {
            let cls: AnyClass? = NSClassFromString("UIWebView")   // VULNERABLE reference
            let present = cls != nil
            return "NSClassFromString(\"UIWebView\") → \(present ? "class present" : "nil (removed in this SDK)")\nThe literal string \"UIWebView\" is embedded in __TEXT and flagged by MASTG-TEST-0331."
        }
    },
    Demo("MASTG-DEMO-0095", "Attacker-controlled WebView URL", test: "MASTG-TEST-0332") { AttackerURLScreen() },
    Demo("MASTG-DEMO-0096", "HTML injection → local file access", test: "MASTG-TEST-0333") { HTMLInjectionScreen() },
    Demo("MASTG-DEMO-0098", "File access in WebView", test: "MASTG-TEST-0335") {
        WebDemoScreen(demoID: "MASTG-DEMO-0098",
                      explanation: "loadFileURL(allowingReadAccessTo:) scoped to the whole home dir, plus allowFileAccessFromFileURLs (covers runtime demo 0099).",
                      mode: .localFile)
    },
    Demo("MASTG-DEMO-0142", "Sensitive data via native bridge", test: "MASTG-TEST-0376") {
        WebDemoScreen(demoID: "MASTG-DEMO-0142",
                      explanation: "A WKScriptMessageHandler hands native secrets to page JavaScript.",
                      mode: .nativeBridge)
    },
    Demo("MASTG-DEMO-0143", "Secret returned via evaluateJavaScript", test: "MASTG-TEST-0377") {
        WebDemoScreen(demoID: "MASTG-DEMO-0143",
                      explanation: "The message handler pushes the secret back into the page using evaluateJavaScript.",
                      mode: .bridgeReturnsSecret)
    },
    Demo("MASTG-DEMO-0144", "Password field in WebView DOM", test: "MASTG-TEST-0378") {
        WebDemoScreen(demoID: "MASTG-DEMO-0144",
                      explanation: "A password <input> rendered inside the WebView DOM with no native secure overlay.",
                      mode: .passwordInDOM)
    },
    Demo("MASTG-DEMO-0145", "DOM inspection without content world", test: "MASTG-TEST-0379") {
        WebDemoScreen(demoID: "MASTG-DEMO-0145",
                      explanation: "evaluateJavaScript reads the DOM in the default page content world (no .defaultClient isolation).",
                      mode: .domInspection)
    },
    Demo("MASTG-DEMO-0146", "Secret written into WebView DOM", test: "MASTG-TEST-0380") {
        WebDemoScreen(demoID: "MASTG-DEMO-0146",
                      explanation: "evaluateJavaScript writes a session token / PAN directly into the page DOM.",
                      mode: .writeSecretToDOM)
    },
]
