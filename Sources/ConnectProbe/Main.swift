import Foundation
import Auth
import ConnectCore

struct Login: Decodable { var email: String; var password: String }
struct Input: Decodable { var configuration: ServiceConfiguration; var owner: Login; var foreign: Login }
func emit(_ value: [String:Any]) { if let data=try? JSONSerialization.data(withJSONObject:value,options:.sortedKeys) { FileHandle.standardOutput.write(data+Data([10])) } }
func require(_ condition: Bool,_ label: String) throws { if !condition { throw ConnectError.invalid(label) } }
func denied(_ label: String,code: Int=403,_ action: () async throws -> Void) async throws {
    do { try await action() } catch ConnectError.service(_,let status) where status==code { return }; throw ConnectError.invalid("Expected refusal: "+label)
}
struct Participant {
    var auth: AuthClient; var access: Access; var keys: DeviceKeys; var service: ConnectService; var engine: ConnectEngine; var disk: ReplicaDisk
}
func participant(_ login: Login,_ name: String,_ config: ServiceConfiguration,_ root: URL) async throws -> Participant {
    let auth=AuthClient(url:config.url.appendingPathComponent("auth/v1"),headers:["apikey":config.publishableKey],
                        storageKey:lowerID(),localStorage:MemoryAuthStorage(),autoRefreshToken:false)
    let session=try await auth.signIn(email:login.email,password:login.password),access=try Access(session:session)
    let keys=try DeviceKeys(name:name)
    let service=ConnectService(configuration:config,keys:keys) { try await Access(session:auth.session) }
    let disk=ReplicaDisk(url:root.appendingPathComponent(keys.id),key:keys.storage)
    return try Participant(auth:auth,access:access,keys:keys,service:service,engine:ConnectEngine(owner:access.owner,keys:keys,service:service,disk:disk),disk:disk)
}
func rawStatus(_ packet: SignedPacket,access: Access,configuration: ServiceConfiguration) async throws -> Int {
    var r=URLRequest(url:configuration.url.appendingPathComponent("functions/v1/connect-device-v1"));r.httpMethod="POST";r.httpBody=try wireEncode(packet)
    r.setValue(configuration.publishableKey,forHTTPHeaderField:"apikey");r.setValue("Bearer "+access.token,forHTTPHeaderField:"Authorization");r.setValue("application/json",forHTTPHeaderField:"Content-Type")
    return (try await URLSession.shared.data(for:r).1 as! HTTPURLResponse).statusCode
}
@main struct Probe {
    static func main() async {
        guard CommandLine.arguments.contains("--fixture") else { emit(["passed":false,"error":"Fixture mode required."]); exit(2) }
        let root=FileManager.default.temporaryDirectory.appendingPathComponent("nero-connect-probe-"+lowerID())
        defer { try? FileManager.default.removeItem(at:root) }
        var passed=[String](); var current="setup"
        func pass(_ name: String) { passed.append(name); emit(["check":name,"passed":true]) }
        do {
            let input=try JSONDecoder().decode(Input.self,from:FileHandle.standardInput.readDataToEndOfFile())
            let config=try ServiceConfiguration(url:input.configuration.url,publishableKey:input.configuration.publishableKey)
            let a=try await participant(input.owner,"Fixture A",config,root)
            var b=try await participant(input.owner,"Fixture B",config,root)
            let foreign=try await participant(input.foreign,"Foreign fixture",config,root)
            let unapproved=try await participant(input.owner,"Unapproved fixture",config,root)
            let expiredJoiner=try await participant(input.foreign,"Expiry fixture",config,root)
            try require(a.access.owner==b.access.owner && a.access.session != b.access.session,"Sessions were not independent")
            pass("independent-native-Auth-sessions-and-device-keys")
            current="bootstrap"
            try await a.engine.bootstrap(); try await foreign.engine.bootstrap(); try await a.engine.sync()
            let expiring=try await foreign.engine.invite()
            try await expiredJoiner.engine.join(expiring.code())
            try await denied("second bootstrap") { try await b.engine.bootstrap() }
            try await denied("unapproved pull") { _=try await unapproved.service.call("pull",["after":0]) }
            pass("single-bootstrap-and-unapproved-device-denial")
            current="request signatures"
            let original=try await a.service.packet("status",[:])
            var bad=original; bad.body="{\"changed\":true}"
            try require(try await rawStatus(bad,access:a.access,configuration:config)==403,"Tampered request accepted")
            bad=original; bad.signature=try b.keys.sign(bad.transcript)
            try require(try await rawStatus(bad,access:a.access,configuration:config)==403,"Wrong signing key accepted")
            try require(try await rawStatus(original,access:foreign.access,configuration:config)==403,"Foreign owner accepted")
            bad=original; bad.millis-=180000; bad.signature=try a.keys.sign(bad.transcript)
            try require(try await rawStatus(bad,access:a.access,configuration:config)==403,"Stale request accepted")
            _=try await a.service.send(original)
            try await denied("request replay",code:409) { _=try await a.service.send(original) }
            pass("server-rejects-tampered-foreign-stale-and-replayed-requests")
            current="invitation"
            let invite=try await a.engine.invite()
            var wrong=invite; wrong.secret=try Data.random(32).hex; wrong.signature=try a.keys.sign(wrong.transcript)
            try await denied("wrong invitation secret") { try await b.engine.join(wrong.code()) }
            try await b.engine.join(invite.code()); try await b.engine.sync(); try await a.engine.sync()
            try await denied("pending read") { _=try await b.service.call("pull",["after":0]) }
            let pending=await a.engine.snapshot().pending
            try require(pending.count==1,"Missing pending approval")
            let phraseA=try await a.engine.comparison(pending[0]),phraseB=try await b.engine.waitingComparison()
            try require(phraseA==phraseB,"Verification codes differ")
            let selfCert=try PairCertificate.create(owner:a.access.owner,invitation:invite.id,keys:b.keys,peer:a.keys.publicKeys)
            try await denied("self approval") { _=try await b.service.call("approve",["invite_id":invite.id,"certificate":try object(selfCert)]) }
            var changed=try PairCertificate.create(owner:a.access.owner,invitation:invite.id,keys:a.keys,peer:b.keys.publicKeys)
            changed.peer.encryption=try unapproved.keys.publicKeys.encryption; changed.signature=try a.keys.sign(changed.transcript)
            try await denied("substituted approval keys") { _=try await a.service.call("approve",["invite_id":invite.id,"certificate":try object(changed)]) }
            try await a.engine.approve(pending[0]); try await a.engine.sync(); try await b.engine.sync()
            try require(await b.engine.snapshot().state.trusted,"Approved device did not trust verified certificate")
            try await denied("used invitation") { try await unapproved.engine.join(invite.code()) }
            pass("one-time-pairing-matching-codes-explicit-approval-and-key-pins")
            current="encrypted shared note"
            let first="Authored sample meeting — next steps 🧊"
            try await a.engine.queue(first)
            let accepted=await a.engine.snapshot().state.outbox[0].envelope
            try await a.engine.sync(); try await b.engine.sync()
            try require(await b.engine.snapshot().state.text==first,"Shared note differs")
            let duplicate=try await a.service.call("publish",["envelope":try object(accepted)])
            try require(duplicate["duplicate"] as? Bool==true,"Duplicate was not idempotent")
            var collision=accepted; collision.revision=lowerID(); collision.signature=try a.keys.sign(collision.transcript)
            try await denied("message ID collision",code:409) { _=try await a.service.call("publish",["envelope":try object(collision)]) }
            var tampered=accepted; tampered.ciphertext=Data("bad".utf8).base64EncodedString()
            try await denied("changed ciphertext") { _=try await a.service.call("publish",["envelope":try object(tampered)]) }
            pass("encrypted-native-shared-state-exact-text-and-idempotent-admission")
            current="durable outbox and lost response"
            try await b.engine.queue("Edit queued before reconnect")
            let queued=await b.engine.snapshot().state.outbox[0].envelope
            _=try await b.service.call("publish",["envelope":try object(queued)]) // deliberately suppress acceptance at engine boundary
            b.engine=try ConnectEngine(owner:b.access.owner,keys:b.keys,service:b.service,disk:b.disk)
            try require(await b.engine.snapshot().state.outbox.first?.envelope==queued,"Outbox bytes changed on reconstruction")
            try await b.engine.bind(); try await b.engine.sync(); try await a.engine.sync()
            try require(await a.engine.snapshot().state.text=="Edit queued before reconnect","Reconnect did not recover state")
            try require(await b.engine.snapshot().state.outbox.isEmpty,"Lost acceptance duplicated queued work")
            pass("encrypted-disk-reconstruction-and-suppressed-acceptance-retry")
            current="concurrent conflict"
            try await a.engine.queue("Concurrent A"); try await b.engine.queue("Concurrent B")
            let engineA=a.engine,engineB=b.engine
            async let s1: Void=engineA.sync(); async let s2: Void=engineB.sync(); _=try await(s1,s2)
            let sa=await a.engine.snapshot(),sb=await b.engine.snapshot()
            try require(sa.state.conflict != sb.state.conflict,"Concurrent edit was silently overwritten")
            let losing=sa.state.conflict ? a.engine : b.engine
            try await losing.sync(); let draft=await losing.snapshot().state.outbox[0].text
            try await losing.keepDraft(); try await losing.sync(); try await a.engine.sync(); try await b.engine.sync()
            try require(await a.engine.snapshot().state.text==draft,"A did not converge after explicit conflict resolution")
            try require(await b.engine.snapshot().state.text==draft,"B did not converge after explicit conflict resolution")
            pass("concurrent-CAS-conflict-retained-and-explicitly-resolved")
            current="revocation and logout"
            try await a.engine.revoke(b.keys.publicKeys)
            try await denied("revoked device") { try await b.engine.sync() }
            try await denied("revoked device bootstrap") { try await b.engine.bootstrap() }
            let beforeLogout=try await a.service.packet("status",[:]); let oldAccess=a.access
            try await a.auth.signOut(scope:.local)
            let logoutHTTP=try await rawStatus(beforeLogout,access:oldAccess,configuration:config)
            emit(["observation":"request-after-sign-out","httpStatus":logoutHTTP])
            try require([401,403].contains(logoutHTTP),"Logged-out session remained authorized")
            pass("revocation-tombstone-and-live-session-invalidation")
            current="server invitation expiry"
            let remaining=max(0,Int64(ceil(Date().timeIntervalSince1970))-expiring.expires)
            _=remaining
            while Int64(Date().timeIntervalSince1970)<=expiring.expires+7 {
                emit(["phase":"waiting-for-server-invitation-expiry","secondsRemaining":max(0,expiring.expires+8-Int64(Date().timeIntervalSince1970))])
                try await Task.sleep(for:.seconds(20))
            }
            let p=try expiredJoiner.keys.publicKeys
            try await denied("expired server invitation") { _=try await expiredJoiner.service.call("join",["invite_id":expiring.id,"secret":expiring.secret,
                "maker_signing":expiring.maker.signing,"maker_encryption":expiring.maker.encryption,"name":"Expiry fixture","keys":["signing":p.signing,"encryption":p.encryption]]) }
            try await expiredJoiner.engine.sync()
            try require(await expiredJoiner.engine.snapshot().status=="unregistered","Expired pending slot was not retired")
            let fresh=try await foreign.engine.invite()
            try await expiredJoiner.engine.join(fresh.code()); try await expiredJoiner.engine.sync()
            try require(await expiredJoiner.engine.snapshot().status=="pending","A fresh pending request was removed by an old invitation")
            pass("server-expiry-retires-pending-slot-and-allows-fresh-pairing")
            emit(["passed":true,"checks":passed,"physicalMacsTested":false,"testLocation":"independent native clients in one local process; real hosted service",
                  "restartScope":"encrypted disk state and engine reconstruction, not an OS process restart","acceptanceLossScope":"deliberately suppressed at client-engine boundary"])
        } catch { emit(["passed":false,"checks":passed,"failedStage":current,"error":(error as? LocalizedError)?.errorDescription ?? "Native fixture failed."]); exit(1) }
    }
}
