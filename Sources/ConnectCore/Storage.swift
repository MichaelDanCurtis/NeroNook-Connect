import Foundation
import Security
import CryptoKit
import Auth

// Independent non-syncing file-Keychain namespace. Accessibility is requested;
// classic macOS Keychain does not establish device-only migration protection.
// No provider/browser/host keychain item is queried.
public struct DeviceVault: AuthLocalStorage, Sendable {
    public let service: String
    public init(service: String="cafe.nero.connect.local") { self.service=service }
    private func query(_ key: String) -> [String:Any] { [kSecClass as String:kSecClassGenericPassword,
        kSecAttrService as String:service,kSecAttrAccount as String:key,kSecAttrSynchronizable as String:false] }
    public func retrieve(key: String) throws -> Data? {
        var q=query(key); q[kSecReturnData as String]=true; q[kSecMatchLimit as String]=kSecMatchLimitOne
        var data: CFTypeRef?; let status=SecItemCopyMatching(q as CFDictionary,&data)
        if status==errSecItemNotFound { return nil }
        guard status==errSecSuccess else { throw ConnectError.invalid("Unlock Keychain to use Connect (\(status)).") }
        return data as? Data
    }
    public func store(key: String,value: Data) throws {
        let q=query(key); let status=SecItemUpdate(q as CFDictionary,[kSecValueData as String:value] as CFDictionary)
        if status==errSecSuccess { return }
        guard status==errSecItemNotFound else { throw ConnectError.invalid("Keychain could not save Connect's private data (\(status)).") }
        var add=q; add[kSecValueData as String]=value; add[kSecAttrAccessible as String]=kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        guard SecItemAdd(add as CFDictionary,nil)==errSecSuccess else { throw ConnectError.invalid("Could not create Connect's Keychain entry.") }
    }
    public func remove(key: String) throws {
        let status=SecItemDelete(query(key) as CFDictionary)
        guard status==errSecSuccess||status==errSecItemNotFound else { throw ConnectError.invalid("Could not remove Connect's Keychain entry.") }
    }
    public func keys(owner: String,name: String) throws -> DeviceKeys {
        let key="device.\(owner)"
        if let bytes=try retrieve(key:key) { return try JSONDecoder().decode(DeviceKeys.self,from:bytes) }
        let keys=try DeviceKeys(name:name); try store(key:key,value:wireEncode(keys)); return keys
    }
    public func replaceKeys(owner: String,name: String) throws {
        if let old=try retrieve(key:"device.\(owner)") {
            try store(key:"retired.device.\(owner).\(old.sha256)",value:old)
        }
        try store(key:"device.\(owner)",value:wireEncode(DeviceKeys(name:name)))
    }
}
public final class MemoryAuthStorage: AuthLocalStorage, @unchecked Sendable {
    private var values=[String:Data](); private let lock=NSLock()
    public init() {}
    public func retrieve(key: String) -> Data? { lock.lock(); defer { lock.unlock() }; return values[key] }
    public func store(key: String,value: Data) { lock.lock(); defer { lock.unlock() }; values[key]=value }
    public func remove(key: String) { lock.lock(); defer { lock.unlock() }; values.removeValue(forKey:key) }
}
public struct QueuedNote: Codable, Sendable { public var envelope: EncryptedNote; public var text: String }
public struct ReplicaState: Codable, Sendable {
    public var owner: String; public var device: String; public var trusted=false; public var peers=[DevicePublic]()
    public var pendingInvitation: Invitation?; public var cursor: Int64=0; public var revision=""
    public var text=""; public var outbox=[QueuedNote](); public var conflict=false
    public init(owner: String,device: String) { self.owner=owner; self.device=device }
}
public struct ReplicaDisk: Sendable {
    public let url: URL; private let key: Data
    public init(url: URL,key: Data) { self.url=url; self.key=key }
    public func load(owner: String,device: String) throws -> ReplicaState {
        guard FileManager.default.fileExists(atPath:url.path) else { return ReplicaState(owner:owner,device:device) }
        let bytes=try Data(contentsOf:url); guard bytes.count<1024*1024 else { throw ConnectError.invalid("Local Connect cache exceeds its limit.") }
        let clear=try AES.GCM.open(AES.GCM.SealedBox(combined:bytes),using:SymmetricKey(data:key),authenticating:Data("nero-connect/cache/1/\(owner)/\(device)".utf8))
        let state=try JSONDecoder().decode(ReplicaState.self,from:clear)
        guard state.owner==owner,state.device==device else { throw ConnectError.invalid("Local device cache mismatch.") }; return state
    }
    public func save(_ state: ReplicaState) throws {
        let clear=try wireEncode(state); guard clear.count<1024*1024 else { throw ConnectError.invalid("Local Connect cache is full.") }
        let sealed=try AES.GCM.seal(clear,using:SymmetricKey(data:key),authenticating:Data("nero-connect/cache/1/\(state.owner)/\(state.device)".utf8))
        let parent=url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at:parent,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        try sealed.combined!.write(to:url,options:.atomic)
        try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:url.path)
    }
}
