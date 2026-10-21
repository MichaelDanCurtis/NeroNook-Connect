import XCTest
import CryptoKit
@testable import ConnectCore

final class ConnectTests: XCTestCase {
    let owner="5784e104-c5b5-4f46-aed1-ab6a8f8b0a32"
    let origin="https://smlbxiktqgqxnzohfnup.supabase.co"
    func testIndependentKeysAndSignatures() throws {
        let a=try DeviceKeys(name:"A"),b=try DeviceKeys(name:"B")
        XCTAssertNotEqual(a.id,b.id); XCTAssertNotEqual(a.signing,b.signing); XCTAssertNotEqual(a.encryption,b.encryption)
        let sig=try a.sign("request")
        XCTAssertTrue(try verified(sig,"request",key:a.publicKeys.signing))
        XCTAssertFalse(try verified(sig,"changed",key:a.publicKeys.signing))
        XCTAssertFalse(try verified(sig,"request",key:b.publicKeys.signing))
    }
    func testInvitationPinsOwnerOriginAndLifetime() throws {
        let keys=try DeviceKeys(name:"A"),i=try Invitation.create(owner:owner,origin:origin,keys:keys)
        XCTAssertEqual(try Invitation.parse(i.code(),owner:owner,origin:origin).secret,i.secret)
        XCTAssertThrowsError(try Invitation.parse(i.code(),owner:lowerID(),origin:origin))
        XCTAssertThrowsError(try Invitation.parse(i.code(),owner:owner,origin:"https://elsewhere.invalid"))
        XCTAssertThrowsError(try Invitation.parse(i.code(),owner:owner,origin:origin,now:Date().addingTimeInterval(400)))
        var changed=i; changed.secret=try Data.random(32).hex
        XCTAssertThrowsError(try Invitation.parse(changed.code(),owner:owner,origin:origin))
        XCTAssertThrowsError(try Invitation.parse("http://bad.invalid",owner:owner,origin:origin))
    }
    func testApprovalBindsBothCompleteIdentities() throws {
        let a=try DeviceKeys(name:"A"),b=try DeviceKeys(name:"B")
        var c=try PairCertificate.create(owner:owner,invitation:lowerID(),keys:a,peer:b.publicKeys)
        XCTAssertTrue(try verified(c.signature,c.transcript,key:a.publicKeys.signing))
        let phrase=c.comparison; c.peer.encryption=try DeviceKeys(name:"impostor").publicKeys.encryption
        XCTAssertFalse(try verified(c.signature,c.transcript,key:a.publicKeys.signing)); XCTAssertNotEqual(c.comparison,phrase)
    }
    func testHPKERoundTripAndWrongRecipient() throws {
        let a=try DeviceKeys(name:"A"),b=try DeviceKeys(name:"B"),other=try DeviceKeys(name:"C")
        let note=try EncryptedNote.seal(text:"Meeting at 10 — café 🧊",owner:owner,keys:a,peer:b.publicKeys,parent:"")
        XCTAssertEqual(try note.open(owner:owner,keys:b,peer:a.publicKeys),"Meeting at 10 — café 🧊")
        XCTAssertThrowsError(try note.open(owner:owner,keys:other,peer:a.publicKeys))
        XCTAssertThrowsError(try note.open(owner:lowerID(),keys:b,peer:a.publicKeys))
        XCTAssertThrowsError(try note.open(owner:owner,keys:b,peer:other.publicKeys))
    }
    func testTamperedHeaderAndCiphertextReject() throws {
        let a=try DeviceKeys(name:"A"),b=try DeviceKeys(name:"B")
        let original=try EncryptedNote.seal(text:"hello",owner:owner,keys:a,peer:b.publicKeys,parent:"")
        for field in 0..<5 {
            var n=original
            switch field { case 0:n.parent=lowerID(); case 1:n.revision=lowerID(); case 2:n.encapsulated=try Data.random(32).hex
            case 3:n.ciphertext=Data("garbage".utf8).base64EncodedString(); default:n.resource=lowerID() }
            XCTAssertThrowsError(try n.open(owner:owner,keys:b,peer:a.publicKeys))
        }
        var validSigBadCipher=original; validSigBadCipher.ciphertext=try Data.random(40).base64EncodedString()
        validSigBadCipher.signature=try a.sign(validSigBadCipher.transcript)
        XCTAssertThrowsError(try validSigBadCipher.open(owner:owner,keys:b,peer:a.publicKeys))
    }
    func testTextBoundAndNoNondeterministicRetry() throws {
        let a=try DeviceKeys(name:"A"),b=try DeviceKeys(name:"B")
        XCTAssertThrowsError(try EncryptedNote.seal(text:String(repeating:"💥",count:1025),owner:owner,keys:a,peer:b.publicKeys,parent:""))
        let n=try EncryptedNote.seal(text:"same bytes",owner:owner,keys:a,peer:b.publicKeys,parent:"")
        let decoded=try JSONDecoder().decode(EncryptedNote.self,from:wireEncode(n))
        XCTAssertEqual(n,decoded); XCTAssertEqual(try wireEncode(n),try wireEncode(decoded))
    }
    func testAtomicEncryptedCacheOutboxAndCursor() throws {
        let keys=try DeviceKeys(name:"A"),peer=try DeviceKeys(name:"B")
        let dir=FileManager.default.temporaryDirectory.appendingPathComponent(lowerID()); defer { try? FileManager.default.removeItem(at:dir) }
        let disk=ReplicaDisk(url:dir.appendingPathComponent("state"),key:keys.storage)
        var state=ReplicaState(owner:owner,device:keys.id); state.text="Sensitive sample draft never stored in plaintext"; state.cursor=42
        state.outbox=[QueuedNote(envelope:try .seal(text:state.text,owner:owner,keys:keys,peer:peer.publicKeys,parent:""),text:state.text)]
        try disk.save(state)
        let bytes=try Data(contentsOf:disk.url)
        XCTAssertNil(bytes.range(of:Data(state.text.utf8)))
        let restored=try disk.load(owner:owner,device:keys.id)
        XCTAssertEqual(restored.cursor,42); XCTAssertEqual(restored.outbox.first?.envelope,state.outbox.first?.envelope)
        XCTAssertEqual(try FileManager.default.attributesOfItem(atPath:disk.url.path)[.posixPermissions] as? Int,0o600)
        XCTAssertThrowsError(try disk.load(owner:lowerID(),device:keys.id))
        XCTAssertThrowsError(try ReplicaDisk(url:disk.url,key:Data.random(32)).load(owner:owner,device:keys.id))
        var damaged=bytes; damaged[20] ^= 1; try damaged.write(to:disk.url)
        XCTAssertThrowsError(try disk.load(owner:owner,device:keys.id))
    }
    func testSignedRequestCoversExactBodyAndSession() throws {
        let keys=try DeviceKeys(name:"A")
        var p=try SignedPacket.create(owner:owner,session:lowerID(),keys:keys,action:"status",body:["foo":"é / bar"])
        XCTAssertTrue(try verified(p.signature,p.transcript,key:keys.publicKeys.signing))
        p.body += " "; XCTAssertFalse(try verified(p.signature,p.transcript,key:keys.publicKeys.signing))
        p=try SignedPacket.create(owner:owner,session:lowerID(),keys:keys,action:"status",body:[:]);p.session=lowerID()
        XCTAssertFalse(try verified(p.signature,p.transcript,key:keys.publicKeys.signing))
    }
    func testConfigurationRejectsWrongRelayAndAdministratorKey() throws {
        XCTAssertThrowsError(try ServiceConfiguration(url:URL(string:"http://smlbxiktqgqxnzohfnup.supabase.co")!,publishableKey:"sb_publishable_test"))
        XCTAssertThrowsError(try ServiceConfiguration(url:URL(string:origin)!,publishableKey:"service_role"))
    }
    func testCallbackRejectsImplicitTokensAndUnexpectedAuthority() {
        XCTAssertTrue(SignInCallback.accepts(URL(string:"cafe.nero.connect://auth-callback?code=opaque")!))
        for url in ["https://auth-callback?code=x","cafe.nero.connect://elsewhere?code=x","cafe.nero.connect://user@auth-callback?code=x", "cafe.nero.connect://auth-callback:80?code=x", "cafe.nero.connect://auth-callback/other?code=x", "cafe.nero.connect://auth-callback?code=x&code=y", "cafe.nero.connect://auth-callback#access_token=opaque"] {
            XCTAssertFalse(SignInCallback.accepts(URL(string:url)!))
        }
    }
}
