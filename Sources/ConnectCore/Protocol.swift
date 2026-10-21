import Foundation
import CryptoKit

public enum ConnectError: Error, LocalizedError {
    case invalid(String), service(String, Int), offline
    public var errorDescription: String? {
        switch self { case .invalid(let s), .service(let s,_): return s
        case .offline: return "Offline. Your saved note and queued edit are kept on this Mac." }
    }
}
public enum SignInCallback {
    public static func accepts(_ url: URL) -> Bool {
        guard url.scheme=="cafe.nero.connect",url.host=="auth-callback",url.user==nil,url.password==nil,url.port==nil,
              url.path.isEmpty || url.path=="/",url.fragment==nil,
              let items=URLComponents(url:url,resolvingAgainstBaseURL:false)?.queryItems else { return false }
        let codes=items.filter{$0.name=="code"}; return codes.count==1 && !(codes[0].value ?? "").isEmpty
    }
}
public func lowerID() -> String { UUID().uuidString.lowercased() }
public func wireEncode<T: Encodable>(_ value: T) throws -> Data {
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys,.withoutEscapingSlashes]; return try e.encode(value)
}
public func object<T: Encodable>(_ value: T) throws -> [String:Any] {
    try JSONSerialization.jsonObject(with: wireEncode(value)) as! [String:Any]
}
public func typed<T: Decodable>(_ type: T.Type, _ object: Any) throws -> T {
    try JSONDecoder().decode(type, from: JSONSerialization.data(withJSONObject: object))
}
extension Data {
    public var hex: String { map { String(format:"%02x",$0) }.joined() }
    public init(hex: String) throws {
        guard hex.count % 2 == 0, hex.count <= 32768, hex.allSatisfy({"0123456789abcdef".contains($0)}) else { throw ConnectError.invalid("Invalid encoded bytes.") }
        self.init(); var i=hex.startIndex
        while i<hex.endIndex { let end=hex.index(i,offsetBy:2); append(UInt8(hex[i..<end],radix:16)!); i=end }
    }
    public static func random(_ count: Int) throws -> Data {
        var bytes=[UInt8](repeating:0,count:count)
        guard SecRandomCopyBytes(kSecRandomDefault,count,&bytes)==errSecSuccess else { throw ConnectError.invalid("Unable to generate secure random bytes.") }
        return Data(bytes)
    }
    public var sha256: String { Data(SHA256.hash(data:self)).hex }
}
import Security

public struct DevicePublic: Codable, Equatable, Sendable, Identifiable {
    public var id: String; public var name: String; public var signing: String; public var encryption: String
    public var status: String?
    public var transcript: String { "\(id)\n\(signing)\n\(encryption)" }
    public var fingerprint: String { Data(transcript.utf8).sha256.prefix(16).uppercased().chunked(4).joined(separator:" ") }
    public func sameKeys(_ other: Self) -> Bool { id==other.id && signing==other.signing && encryption==other.encryption }
}
extension String {
    func chunked(_ count: Int) -> [String] { stride(from:0,to:self.count,by:count).map { n in
        String(dropFirst(n).prefix(count)) } }
}
public struct DeviceKeys: Codable, Sendable {
    public var id: String; public var name: String; public var signing: Data; public var encryption: Data; public var storage: Data
    public init(name: String) throws { id=lowerID(); self.name=String(name.prefix(64)); signing=Curve25519.Signing.PrivateKey().rawRepresentation
        encryption=Curve25519.KeyAgreement.PrivateKey().rawRepresentation; storage=try .random(32) }
    public var publicKeys: DevicePublic { get throws { DevicePublic(id:id,name:name,
        signing:try Curve25519.Signing.PrivateKey(rawRepresentation:signing).publicKey.rawRepresentation.hex,
        encryption:try Curve25519.KeyAgreement.PrivateKey(rawRepresentation:encryption).publicKey.rawRepresentation.hex) } }
    public func sign(_ text: String) throws -> String { try Curve25519.Signing.PrivateKey(rawRepresentation:signing).signature(for:Data(text.utf8)).hex }
}
public func verified(_ signature: String, _ text: String, key: String) throws -> Bool {
    guard key.count==64,signature.count==128 else { return false }
    return try Curve25519.Signing.PublicKey(rawRepresentation:Data(hex:key)).isValidSignature(Data(hex:signature),for:Data(text.utf8))
}
public struct Invitation: Codable, Sendable {
    public var origin: String; public var owner: String; public var id: String; public var maker: DevicePublic
    public var secret: String; public var expires: Int64; public var signature: String
    public var transcript: String { "nero-connect/invite/1\n\(origin)\n\(owner)\n\(id)\n\(expires)\n\(maker.transcript)\n\(secret)" }
    public static func create(owner: String,origin: String,keys: DeviceKeys,now: Date=Date()) throws -> Self {
        var i=Self(origin:origin,owner:owner,id:lowerID(),maker:try keys.publicKeys,secret:try Data.random(32).hex,
                   expires:Int64(now.timeIntervalSince1970)+295,signature:"")
        i.signature=try keys.sign(i.transcript); return i
    }
    public func code() throws -> String { "NERO1." + (try wireEncode(self)).base64EncodedString() }
    public static func parse(_ text: String, owner: String,origin: String,now: Date=Date()) throws -> Self {
        let text=text.trimmingCharacters(in:.whitespacesAndNewlines)
        guard text.hasPrefix("NERO1."),text.count<4096,let bytes=Data(base64Encoded:String(text.dropFirst(6))) else { throw ConnectError.invalid("Paste the complete NERO1 pairing code.") }
        let i=try JSONDecoder().decode(Self.self,from:bytes)
        guard i.owner==owner,i.origin==origin,i.expires>Int64(now.timeIntervalSince1970),i.expires<=Int64(now.timeIntervalSince1970)+360,
              i.secret.count==64,try verified(i.signature,i.transcript,key:i.maker.signing) else { throw ConnectError.invalid("Pairing code expired, belongs to another account, or was changed.") }
        return i
    }
}
public struct PairCertificate: Codable, Sendable {
    public var owner: String; public var invitation: String; public var maker: DevicePublic; public var peer: DevicePublic; public var signature: String
    public var transcript: String { "nero-connect/approval/1\n\(owner)\n\(invitation)\n\(maker.transcript)\n\(peer.transcript)" }
    public static func create(owner: String,invitation: String,keys: DeviceKeys,peer: DevicePublic) throws -> Self {
        var c=Self(owner:owner,invitation:invitation,maker:try keys.publicKeys,peer:peer,signature:"")
        c.signature=try keys.sign(c.transcript); return c
    }
    public var comparison: String { Data(transcript.utf8).sha256.prefix(12).uppercased().chunked(4).joined(separator:" · ") }
}
public struct EncryptedNote: Codable, Equatable, Sendable {
    public var owner: String; public var id: String; public var sender: String; public var recipient: String
    public var resource: String; public var revision: String; public var parent: String
    public var encapsulated: String; public var ciphertext: String; public var signature: String
    public static let resourceID="5f7bd1d6-8734-4dbe-a0ef-48657001cc11"
    public var header: String { "nero-connect/payload/1\n\(owner)\n\(id)\n\(sender)\n\(recipient)\n\(resource)\n\(revision)\n\(parent)" }
    public var transcript: String { "nero-connect/note/1\n\(owner)\n\(id)\n\(sender)\n\(recipient)\n\(resource)\n\(revision)\n\(parent)\n\(encapsulated)\n\(ciphertext)" }
    public static func seal(text: String,owner: String,keys: DeviceKeys,peer: DevicePublic,parent: String) throws -> Self {
        guard text.utf8.count<=4096 else { throw ConnectError.invalid("Keep the pilot note under 4 KiB.") }
        var note=Self(owner:owner,id:lowerID(),sender:keys.id,recipient:peer.id,resource:resourceID,revision:lowerID(),parent:parent,encapsulated:"",ciphertext:"",signature:"")
        var sender=try HPKE.Sender(recipientKey:Curve25519.KeyAgreement.PublicKey(rawRepresentation:Data(hex:peer.encryption)),
                                   ciphersuite:.Curve25519_SHA256_ChachaPoly,info:Data(note.header.utf8))
        note.encapsulated=sender.encapsulatedKey.hex
        note.ciphertext=try sender.seal(wireEncode(["text":text]),authenticating:Data(note.header.utf8)).base64EncodedString()
        note.signature=try keys.sign(note.transcript); return note
    }
    public func open(owner: String,keys: DeviceKeys,peer: DevicePublic) throws -> String {
        guard self.owner==owner,sender==peer.id,recipient==keys.id,resource==Self.resourceID,
              try verified(signature,transcript,key:peer.signing),let ciphertext=Data(base64Encoded:ciphertext),ciphertext.count<=8192 else { throw ConnectError.invalid("An unverified update was held for review; saved data was kept.") }
        var receiver=try HPKE.Recipient(privateKey:Curve25519.KeyAgreement.PrivateKey(rawRepresentation:keys.encryption),
                                       ciphersuite:.Curve25519_SHA256_ChachaPoly,info:Data(header.utf8),encapsulatedKey:Data(hex:encapsulated))
        let clear=try receiver.open(ciphertext,authenticating:Data(header.utf8))
        let value=try JSONDecoder().decode([String:String].self,from:clear)
        guard let text=value["text"],text.utf8.count<=4096 else { throw ConnectError.invalid("Invalid shared note.") }; return text
    }
}
public struct SignedPacket: Codable, Sendable {
    public var owner: String; public var session: String; public var device: String; public var nonce: String
    public var millis: Int64; public var action: String; public var body: String; public var signature: String
    public var transcript: String { "nero-connect/request/1\n\(owner)\n\(session)\n\(device)\n\(nonce)\n\(millis)\n\(action)\n\(Data(body.utf8).sha256)" }
    public static func create(owner: String,session: String,keys: DeviceKeys,action: String,body: [String:Any]) throws -> Self {
        let bytes=try JSONSerialization.data(withJSONObject:body,options:[.sortedKeys,.withoutEscapingSlashes])
        guard bytes.count<=32768 else { throw ConnectError.invalid("Request too large.") }
        var p=Self(owner:owner,session:session,device:keys.id,nonce:lowerID(),millis:Int64(Date().timeIntervalSince1970*1000),action:action,
                   body:String(decoding:bytes,as:UTF8.self),signature:"")
        p.signature=try keys.sign(p.transcript); return p
    }
}
