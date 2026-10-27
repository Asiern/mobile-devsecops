//
//  NetworkingDemos.swift
//  Vulnerable
//
//  MASTG transport-security demos (code side; the Info.plist ATS demos live in
//  Info.plist). EDUCATIONAL ONLY.
//

import Foundation
import Network
import SwiftUI

enum NetworkingDemos {

    // MARK: MASTG-DEMO-0084 — Hardcoded HTTP URLs in iOS Binary (MASTG-TEST-0321)
    /// Cleartext endpoints hardcoded as string literals (recoverable via strings).
    static let loginEndpoint = "http://api.example.com/login"           // VULNERABLE: http
    static let telemetryEndpoint = "http://telemetry.example.com/track" // VULNERABLE: http

    static func hardcodedHTTPURLs() -> String {
        let urls = [loginEndpoint, telemetryEndpoint, "http://cdn.example.com/config.json"]
        var task: URLSessionDataTask?
        if let u = URL(string: loginEndpoint) {
            task = URLSession.shared.dataTask(with: u) { _, _, _ in }
        }
        _ = task
        return "Hardcoded cleartext endpoints:\n" + urls.joined(separator: "\n")
    }

    // MARK: MASTG-DEMO-0110 — URLSession Minimum TLS Version Lowered (MASTG-TEST-0343)
    /// Lowers the session's minimum TLS version to TLS 1.0.
    static func lowerURLSessionTLS() -> String {
        let config = URLSessionConfiguration.default
        config.tlsMinimumSupportedProtocolVersion = .TLSv10   // VULNERABLE: allows TLS 1.0/1.1
        _ = URLSession(configuration: config)
        return "URLSessionConfiguration.tlsMinimumSupportedProtocolVersion = .TLSv10\n(TLS 1.0/1.1 are deprecated and insecure)."
    }

    // MARK: MASTG-DEMO-0085 — Network Framework Bypassing ATS (MASTG-TEST-0323)
    /// Raw TCP via Network.framework (no TLS) — ATS does not cover NWConnection,
    /// so plaintext traffic flows freely.
    static func networkFrameworkCleartext() -> String {
        let host = NWEndpoint.Host("api.example.com")
        let port = NWEndpoint.Port(rawValue: 80)!
        let connection = NWConnection(host: host, port: port, using: .tcp) // VULNERABLE: .tcp, no TLS
        connection.stateUpdateHandler = { _ in }
        connection.start(queue: .global())
        connection.cancel()
        return "Opened an NWConnection over plain .tcp to port 80 — bypasses ATS entirely."
    }

    // MARK: MASTG-DEMO-0111 — Network.framework TLS Minimum Lowered (MASTG-TEST-0344)
    /// Lowers the minimum TLS version on a Network.framework TLS connection via
    /// sec_protocol_options.
    static func networkFrameworkLowerTLS() -> String {
        let tlsOptions = NWProtocolTLS.Options()
        sec_protocol_options_set_min_tls_protocol_version(
            tlsOptions.securityProtocolOptions, .TLSv10)       // VULNERABLE
        let params = NWParameters(tls: tlsOptions)
        _ = NWConnection(host: "api.example.com", port: 443, using: params)
        return "sec_protocol_options_set_min_tls_protocol_version(..., .TLSv10) — downgrades the floor to TLS 1.0."
    }

    // MARK: MASTG-DEMO-0086 — BSD Sockets Bypassing ATS (MASTG-TEST-0323)
    /// A raw BSD socket connecting on port 80. ATS has no visibility into this.
    static func bsdSocketCleartext() -> String {
        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)   // VULNERABLE: raw socket
        guard fd >= 0 else { return "socket() failed" }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(80).bigEndian
        addr.sin_addr.s_addr = inet_addr("93.184.216.34")
        let connected = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        close(fd)
        return "Opened a raw BSD socket to port 80 (connect result=\(connected)) — invisible to ATS."
    }

    // MARK: MASTG-DEMO-0154 — URLSessionDelegate Accepting Any Server Certificate (MASTG-TEST-0396)
    /// A delegate that blindly trusts whatever certificate the server presents
    /// (classic MITM enabler).
    static func urlSessionTrustAll() -> String {
        let delegate = TrustAllSessionDelegate()
        let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
        let task = session.dataTask(with: URL(string: "https://self-signed.badssl.com")!) { _, _, _ in }
        _ = task
        return "URLSessionDelegate returns .useCredential with the server's own trust for every challenge — accepts any certificate (even self-signed)."
    }
}

/// VULNERABLE URLSession delegate: accepts any server certificate (0154).
final class TrustAllSessionDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if let trust = challenge.protectionSpace.serverTrust {
            // VULNERABLE: no evaluation, no pinning — trust everything.
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}

let networkingDemos: [Demo] = [
    Demo("MASTG-DEMO-0084", "Hardcoded HTTP URLs", test: "MASTG-TEST-0321") {
        RunnerView(demoID: "MASTG-DEMO-0084",
                   explanation: "Cleartext http:// endpoints hardcoded as string literals in the binary.",
                   action: NetworkingDemos.hardcodedHTTPURLs)
    },
    Demo("MASTG-DEMO-0085", "Network.framework bypassing ATS", test: "MASTG-TEST-0323") {
        RunnerView(demoID: "MASTG-DEMO-0085",
                   explanation: "Plain TCP via NWConnection on port 80 — ATS does not cover Network.framework.",
                   action: NetworkingDemos.networkFrameworkCleartext)
    },
    Demo("MASTG-DEMO-0086", "BSD sockets bypassing ATS", test: "MASTG-TEST-0323") {
        RunnerView(demoID: "MASTG-DEMO-0086",
                   explanation: "A raw BSD socket to port 80 — invisible to ATS.",
                   action: NetworkingDemos.bsdSocketCleartext)
    },
    Demo("MASTG-DEMO-0110", "URLSession min TLS lowered", test: "MASTG-TEST-0343") {
        RunnerView(demoID: "MASTG-DEMO-0110",
                   explanation: "tlsMinimumSupportedProtocolVersion set to .TLSv10 in code.",
                   action: NetworkingDemos.lowerURLSessionTLS)
    },
    Demo("MASTG-DEMO-0111", "Network.framework TLS lowered", test: "MASTG-TEST-0344") {
        RunnerView(demoID: "MASTG-DEMO-0111",
                   explanation: "sec_protocol_options_set_min_tls_protocol_version lowered to TLS 1.0.",
                   action: NetworkingDemos.networkFrameworkLowerTLS)
    },
    Demo("MASTG-DEMO-0154", "URLSession trusts any cert", test: "MASTG-TEST-0396") {
        RunnerView(demoID: "MASTG-DEMO-0154",
                   explanation: "A URLSessionDelegate that accepts any server certificate.",
                   action: NetworkingDemos.urlSessionTrustAll)
    },
]
