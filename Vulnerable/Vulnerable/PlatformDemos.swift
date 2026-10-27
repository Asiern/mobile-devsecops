//
//  PlatformDemos.swift
//  Vulnerable
//
//  MASTG platform-interaction, anti-tampering and detection demos.
//  EDUCATIONAL ONLY.
//

import Foundation
import CoreLocation
import SwiftUI
import UIKit
import MachO

enum PlatformDemos {

    // MARK: MASTG-DEMO-0134 — Custom URL Scheme Handler Without Input Validation (MASTG-TEST-0370)
    /// Acts on a deep link with no validation of the source or the parameters.
    /// e.g. vulnerable://transfer?to=attacker&amount=9999
    static func handleURLWithoutValidation(_ url: URL) -> String {
        let comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
        let params = comps?.queryItems ?? []
        // VULNERABLE: trusts host/params blindly; no sender check, no allow-list.
        switch url.host {
        case "transfer":
            let to = params.first { $0.name == "to" }?.value ?? "?"
            let amount = params.first { $0.name == "amount" }?.value ?? "?"
            return "Executed transfer of \(amount) to \(to) — no validation performed."
        default:
            return "Handled \(url.absoluteString) with no validation."
        }
    }

    // MARK: MASTG-DEMO-0135 — Custom URL Scheme Handler WITH Source Validation (MASTG-TEST-0371)
    /// The mitigated pattern: only acts when the opening app is on an allow-list.
    static let allowedSourceApps: Set<String> = ["com.apple.mobilesafari", "asiern.Trusted"]

    static func handleURLWithSourceValidation(_ url: URL, sourceApp: String?) -> String {
        guard let sourceApp, allowedSourceApps.contains(sourceApp) else {
            return "Rejected \(url.absoluteString): source app \"\(sourceApp ?? "nil")\" not in allow-list."
        }
        return "Accepted \(url.absoluteString) from trusted source \(sourceApp)."
    }

    // MARK: MASTG-DEMO-0149 — Object Deserialization of a URL Scheme Payload (MASTG-TEST-0386)
    /// Decodes a base64 payload from a deep link using insecure unarchiving
    /// (secure coding disabled), enabling object-injection style attacks.
    static func deserializeURLPayload(_ url: URL) -> String {
        let b64 = URLComponents(url: url, resolvingAgainstBaseURL: false)?
            .queryItems?.first { $0.name == "data" }?.value ?? ""
        guard let data = Data(base64Encoded: b64) else {
            // Produce a sample archive so the demo shows the sink in action.
            let sample = try? NSKeyedArchiver.archivedData(withRootObject: ["role": "user"],
                                                           requiringSecureCoding: false)
            return "No ?data= payload. The sink below unarchives attacker bytes with secure coding OFF.\nSample archive size: \(sample?.count ?? 0) bytes."
        }
        // VULNERABLE: secure coding disabled, arbitrary classes instantiated.
        let unarchiver = try? NSKeyedUnarchiver(forReadingFrom: data)
        unarchiver?.requiresSecureCoding = false
        let obj = unarchiver?.decodeObject(forKey: NSKeyedArchiveRootObjectKey)
        return "Deserialized URL payload with secureCoding=false → \(String(describing: obj))"
    }

    // MARK: MASTG-DEMO-0153 — Universal Link Handler Without Input Validation (MASTG-TEST-0395)
    static func handleUniversalLink(_ url: URL) -> String {
        // VULNERABLE: opens whatever path/redirect is supplied, no host/path allow-list.
        let next = URLComponents(url: url, resolvingAgainstBaseURL: false)?
            .queryItems?.first { $0.name == "redirect" }?.value
        if let next {
            return "Universal link would navigate to redirect=\(next) with no validation (open-redirect)."
        }
        return "Universal link \(url.path) handled with no validation."
    }

    // MARK: MASTG-DEMO-0021 — Jailbreak Detection Techniques (MASTG-TEST-0240)
    static func jailbreakChecks() -> String {
        var hits: [String] = []
        let paths = ["/Applications/Cydia.app", "/Library/MobileSubstrate/MobileSubstrate.dylib",
                     "/bin/bash", "/usr/sbin/sshd", "/etc/apt", "/private/var/lib/apt/"]
        for p in paths where FileManager.default.fileExists(atPath: p) { hits.append(p) }
        // Can we write outside the sandbox?
        let probe = "/private/jailbreak_probe.txt"
        if (try? "x".write(toFile: probe, atomically: true, encoding: .utf8)) != nil {
            hits.append("sandbox-escape(write \(probe))")
            try? FileManager.default.removeItem(atPath: probe)
        }
        // Can we open a known jailbreak URL scheme?
        if let u = URL(string: "cydia://package/com.example"),
           UIApplication.shared.canOpenURL(u) { hits.append("cydia:// scheme") }
        return hits.isEmpty
            ? "No jailbreak indicators (checked \(paths.count) paths + sandbox + cydia://). A Frida hook can force this result."
            : "Jailbreak indicators found:\n" + hits.joined(separator: "\n")
    }

    // MARK: MASTG-DEMO-0131 — Virtual Device (Simulator) Detection (MASTG-TEST-0367)
    static func virtualDeviceChecks() -> String {
        var hits: [String] = []
        #if targetEnvironment(simulator)
        hits.append("#if targetEnvironment(simulator) is true")
        #endif
        let env = ProcessInfo.processInfo.environment
        if env["SIMULATOR_DEVICE_NAME"] != nil { hits.append("SIMULATOR_DEVICE_NAME env set") }
        if env["SIMULATOR_UDID"] != nil { hits.append("SIMULATOR_UDID env set") }
        return hits.isEmpty ? "No virtual-device indicators (running on hardware)."
                            : "Virtual device detected:\n" + hits.joined(separator: "\n")
    }

    // MARK: MASTG-DEMO-0118 — Detecting Frida Hooks Before Crypto (MASTG-TEST-0354)
    /// Checks loaded images for Frida/gadget signatures before doing crypto.
    static func detectFridaModules() -> String {
        var hits: [String] = []
        let suspicious = ["frida", "gadget", "cynject", "cycript"]
        for i in 0..<_dyld_image_count() {
            if let name = _dyld_get_image_name(i) {
                let n = String(cString: name).lowercased()
                if suspicious.contains(where: n.contains) { hits.append(n) }
            }
        }
        return hits.isEmpty ? "No Frida modules among \(_dyld_image_count()) loaded images. (Only then would crypto proceed.)"
                            : "Frida instrumentation detected:\n" + hits.joined(separator: "\n")
    }

    // MARK: MASTG-DEMO-0119 — Frida D-Bus Port Detection (MASTG-TEST-0354)
    /// Probes the default Frida control port (27042) on localhost.
    static func detectFridaPort() -> String {
        let port: UInt16 = 27042
        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else { return "socket() failed" }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let r = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return r == 0 ? "Frida default D-Bus port \(port) is OPEN — instrumentation present."
                      : "Frida port \(port) closed (connect=\(r)). This check is itself bypassable by rebinding Frida's port."
    }
}

// MARK: - Location demo (0126)

/// MASTG-DEMO-0126 — Runtime location capture whose Info.plist purpose string is
/// deceptive (says "weather" but the data is exfiltrated for tracking).
@Observable
final class DeceptiveLocationManager: NSObject, CLLocationManagerDelegate {
    private let manager = CLLocationManager()
    var status = "idle"

    func request() {
        manager.delegate = self
        manager.requestWhenInUseAuthorization()  // purpose string: see Info.plist (deceptive)
        manager.requestLocation()
        status = "Requested precise location using the 'weather personalization' purpose string."
    }

    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        guard let loc = locations.last else { return }
        // VULNERABLE: precise coordinates captured under a misleading justification.
        status = "Captured \(loc.coordinate.latitude), \(loc.coordinate.longitude) — would be exfiltrated for tracking."
    }
    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        status = "location error: \(error.localizedDescription)"
    }
}

private struct LocationDemoView: View {
    @State private var mgr = DeceptiveLocationManager()
    var body: some View {
        RunnerView(demoID: "MASTG-DEMO-0126",
                   explanation: "Requests precise location under a deceptive Info.plist purpose string ('weather personalization') while really tracking the user.",
                   actionTitle: "Request location") {
            mgr.request(); return mgr.status
        }
    }
}

let platformDemos: [Demo] = [
    Demo("MASTG-DEMO-0134", "URL scheme — no validation", test: "MASTG-TEST-0370") {
        RunnerView(demoID: "MASTG-DEMO-0134",
                   explanation: "Processes vulnerable://transfer?to=attacker&amount=9999 with no source/param validation.") {
            PlatformDemos.handleURLWithoutValidation(URL(string: "vulnerable://transfer?to=attacker&amount=9999")!)
        }
    },
    Demo("MASTG-DEMO-0135", "URL scheme — source validation", test: "MASTG-TEST-0371") {
        RunnerView(demoID: "MASTG-DEMO-0135",
                   explanation: "The mitigated pattern: deep link acted on only when the opening app is allow-listed. Shows a rejected untrusted source.") {
            let u = URL(string: "vulnerable://transfer?to=bob&amount=10")!
            return PlatformDemos.handleURLWithSourceValidation(u, sourceApp: "com.evil.app") + "\n" +
                   PlatformDemos.handleURLWithSourceValidation(u, sourceApp: "com.apple.mobilesafari")
        }
    },
    Demo("MASTG-DEMO-0149", "Insecure URL payload deserialization", test: "MASTG-TEST-0386") {
        RunnerView(demoID: "MASTG-DEMO-0149",
                   explanation: "Unarchives a deep-link payload with NSKeyedUnarchiver and secure coding disabled.") {
            PlatformDemos.deserializeURLPayload(URL(string: "vulnerable://load?data=")!)
        }
    },
    Demo("MASTG-DEMO-0153", "Universal link — no validation", test: "MASTG-TEST-0395") {
        RunnerView(demoID: "MASTG-DEMO-0153",
                   explanation: "Follows a ?redirect= target from a universal link with no host/path allow-list (open redirect).") {
            PlatformDemos.handleUniversalLink(URL(string: "https://vulnerable.example.com/go?redirect=https://evil.example")!)
        }
    },
    Demo("MASTG-DEMO-0126", "Deceptive location purpose string", test: "MASTG-TEST-0361") { LocationDemoView() },
    Demo("MASTG-DEMO-0021", "Jailbreak detection", test: "MASTG-TEST-0240") {
        RunnerView(demoID: "MASTG-DEMO-0021",
                   explanation: "Classic jailbreak checks: known paths, sandbox-escape write, cydia:// scheme.",
                   action: PlatformDemos.jailbreakChecks)
    },
    Demo("MASTG-DEMO-0131", "Virtual device detection", test: "MASTG-TEST-0367") {
        RunnerView(demoID: "MASTG-DEMO-0131",
                   explanation: "Detects the simulator via build flag and SIMULATOR_* environment variables.",
                   action: PlatformDemos.virtualDeviceChecks)
    },
    Demo("MASTG-DEMO-0118", "Detect Frida before crypto", test: "MASTG-TEST-0354") {
        RunnerView(demoID: "MASTG-DEMO-0118",
                   explanation: "Scans loaded dyld images for Frida/gadget/cycript before performing crypto.",
                   action: PlatformDemos.detectFridaModules)
    },
    Demo("MASTG-DEMO-0119", "Detect Frida D-Bus port", test: "MASTG-TEST-0354") {
        RunnerView(demoID: "MASTG-DEMO-0119",
                   explanation: "Probes the default Frida control port 27042 on localhost (itself bypassable by rebinding the port).",
                   action: PlatformDemos.detectFridaPort)
    },
]
