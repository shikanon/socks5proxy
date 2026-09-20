import Foundation
import Security

enum ProfileStore {
    // Both targets share a dedicated Keychain access group through entitlements.
    // AfterFirstUnlockThisDeviceOnly allows the extension to reconnect while locked.
    private static let account = "tunnel-profile"
    private static var service: String {
        let bundle = Bundle.main.bundleIdentifier ?? "com.shikanon.socks5proxy"
        return bundle.replacingOccurrences(of: ".PacketTunnel", with: "") + ".profile"
    }

    static func save(_ json: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let values: [String: Any] = [
            kSecValueData as String: Data(json.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        var status = SecItemUpdate(query as CFDictionary, values as CFDictionary)
        if status == errSecItemNotFound {
            var add = query
            values.forEach { add[$0] = $1 }
            status = SecItemAdd(add as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw keychainError(status) }
        var referenceQuery = query
        referenceQuery[kSecReturnPersistentRef as String] = true
        var result: CFTypeRef?
        status = SecItemCopyMatching(referenceQuery as CFDictionary, &result)
        guard status == errSecSuccess, let reference = result as? Data else {
            throw keychainError(status)
        }
        return reference
    }

    static func load(reference: Data) throws -> String {
        let query: [String: Any] = [
            kSecValuePersistentRef as String: reference,
            kSecReturnData as String: true,
            kSecClass as String: kSecClassGenericPassword
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data,
              let json = String(data: data, encoding: .utf8) else {
            throw keychainError(status)
        }
        return json
    }

    private static func keychainError(_ code: OSStatus) -> NSError {
        NSError(domain: NSOSStatusErrorDomain, code: Int(code),
                userInfo: [NSLocalizedDescriptionKey: "无法访问 VPN 配置 Keychain（\(code)）"])
    }
}
