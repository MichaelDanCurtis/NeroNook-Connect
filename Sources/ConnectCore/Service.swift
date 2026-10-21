import Foundation
import Auth

public struct Access: Sendable {
    public let owner: String; public let session: String; public let token: String
    public init(session: Session) throws {
        owner=session.user.id.uuidString.lowercased(); token=session.accessToken
        let parts=token.split(separator:"."); guard parts.count==3 else { throw ConnectError.invalid("Invalid sign-in session.") }
        var body=String(parts[1]).replacingOccurrences(of:"-",with:"+").replacingOccurrences(of:"_",with:"/")
        body += String(repeating:"=",count:(4-body.count%4)%4)
        guard let bytes=Data(base64Encoded:body),let claims=try JSONSerialization.jsonObject(with:bytes) as? [String:Any],
              let id=claims["session_id"] as? String else { throw ConnectError.invalid("Sign in again to create a device session.") }
        self.session=id
    }
}
public struct ServiceConfiguration: Codable, Sendable {
    public let url: URL; public let publishableKey: String
    public init(url: URL,publishableKey: String) throws {
        guard url.absoluteString=="https://smlbxiktqgqxnzohfnup.supabase.co",publishableKey.hasPrefix("sb_publishable_") else {
            throw ConnectError.invalid("This local pilot is restricted to its configured test service.") }
        self.url=url; self.publishableKey=publishableKey
    }
}
private final class NoRedirect: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession,task: URLSessionTask,willPerformHTTPRedirection response: HTTPURLResponse,newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?)->Void) { completionHandler(nil) }
}
public final class ConnectService: @unchecked Sendable {
    public let configuration: ServiceConfiguration; public let keys: DeviceKeys
    private let credentials: @Sendable () async throws -> Access
    private let session: URLSession
    public init(configuration: ServiceConfiguration,keys: DeviceKeys,credentials: @escaping @Sendable () async throws -> Access) {
        self.configuration=configuration; self.keys=keys; self.credentials=credentials
        let c=URLSessionConfiguration.ephemeral; c.httpShouldSetCookies=false; c.httpCookieStorage=nil
        c.urlCache=nil; c.requestCachePolicy = .reloadIgnoringLocalCacheData; c.timeoutIntervalForRequest=20
        session=URLSession(configuration:c,delegate:NoRedirect(),delegateQueue:nil)
    }
    public func packet(_ action: String,_ body: [String:Any]) async throws -> SignedPacket {
        let access=try await credentials()
        return try .create(owner:access.owner,session:access.session,keys:keys,action:action,body:body)
    }
    public func call(_ action: String,_ body: [String:Any]=[:]) async throws -> [String:Any] {
        try await send(packet(action,body))
    }
    public func send(_ packet: SignedPacket) async throws -> [String:Any] {
        try Task.checkCancellation()
        let access=try await credentials()
        guard access.owner==packet.owner,access.session==packet.session else { throw ConnectError.invalid("Sign-in changed. Try again.") }
        var request=URLRequest(url:configuration.url.appendingPathComponent("functions/v1/connect-device-v1"))
        request.httpMethod="POST"; request.setValue(configuration.publishableKey,forHTTPHeaderField:"apikey")
        request.setValue("Bearer "+access.token,forHTTPHeaderField:"Authorization")
        request.setValue("application/json",forHTTPHeaderField:"Content-Type"); request.httpBody=try wireEncode(packet)
        do {
            let (data,response)=try await session.data(for:request)
            try Task.checkCancellation()
            guard data.count<=1024*1024,let response=response as? HTTPURLResponse,
                  response.url?.host==configuration.url.host,let result=try JSONSerialization.jsonObject(with:data) as? [String:Any] else {
                throw ConnectError.invalid("Unexpected service response; local data was kept.") }
            guard response.statusCode==200 else { throw ConnectError.service(result["error"] as? String ?? "Connect is unavailable. Try again.",response.statusCode) }
            return result
        } catch let e as URLError where [.notConnectedToInternet,.networkConnectionLost,.timedOut,.cannotConnectToHost,.cannotFindHost].contains(e.code) { throw ConnectError.offline }
    }
}
public struct PendingPair: Codable, Sendable, Identifiable {
    public var id: String; public var expires: Int64; public var device: DevicePublic
}
public struct ConnectSnapshot: Sendable {
    public var state: ReplicaState; public var pending: [PendingPair]; public var status: String; public var activePeers: [DevicePublic]
}
public actor ConnectEngine {
    public let owner: String; public let keys: DeviceKeys; public let service: ConnectService
    private let disk: ReplicaDisk
    private var state: ReplicaState; private var status="unregistered"; private var pending=[PendingPair](); private var activePeers=[DevicePublic]()
    private var busy=false
    public init(owner: String,keys: DeviceKeys,service: ConnectService,disk: ReplicaDisk) throws {
        self.owner=owner; self.keys=keys; self.service=service; self.disk=disk; state=try disk.load(owner:owner,device:keys.id)
    }
    private func commit(_ new: ReplicaState) throws { try disk.save(new); state=new }
    public func snapshot() -> ConnectSnapshot { .init(state:state,pending:pending,status:status,activePeers:activePeers) }
    private func identityBody() throws -> [String:Any] { ["keys":["signing":try keys.publicKeys.signing,"encryption":try keys.publicKeys.encryption],"name":keys.name] }
    public func inspect() async throws -> [String:Any] { try await service.call("inspect",identityBody()) }
    public func bind() async throws { _=try await service.call("bind") }
    public func bootstrap() async throws {
        _=try await service.call("bootstrap",identityBody()); var next=state; next.trusted=true; try commit(next); status="trusted"
    }
    public func invite() async throws -> Invitation {
        let i=try Invitation.create(owner:owner,origin:service.configuration.url.absoluteString,keys:keys)
        _=try await service.call("invite",["id":i.id,"secret_hash":Data(i.secret.utf8).sha256]); return i
    }
    public func join(_ code: String) async throws {
        let i=try Invitation.parse(code,owner:owner,origin:service.configuration.url.absoluteString)
        var next=state; next.pendingInvitation=i; try commit(next)
        var body=try identityBody(); body["invite_id"]=i.id; body["secret"]=i.secret
        body["maker_signing"]=i.maker.signing; body["maker_encryption"]=i.maker.encryption
        _=try await service.call("join",body); status="pending"
    }
    public func comparison(_ request: PendingPair) throws -> String {
        try PairCertificate.create(owner:owner,invitation:request.id,keys:keys,peer:request.device).comparison
    }
    public func waitingComparison() throws -> String? {
        guard let i=state.pendingInvitation else { return nil }
        return PairCertificate(owner:owner,invitation:i.id,maker:i.maker,peer:try keys.publicKeys,signature:"").comparison
    }
    public func approve(_ request: PendingPair) async throws {
        let cert=try PairCertificate.create(owner:owner,invitation:request.id,keys:keys,peer:request.device)
        _=try await service.call("approve",["invite_id":request.id,"certificate":try object(cert)])
        try apply(cert)
    }
    private func apply(_ c: PairCertificate) throws {
        let me=try keys.publicKeys
        guard c.owner==owner,try verified(c.signature,c.transcript,key:c.maker.signing) else { throw ConnectError.invalid("Unverified pairing approval.") }
        let peer: DevicePublic
        if c.maker.sameKeys(me) { peer=c.peer }
        else {
            let pinned=state.pendingInvitation?.maker ?? state.peers.first(where:{$0.id==c.maker.id})
            guard c.peer.sameKeys(me),let pinned,pinned.sameKeys(c.maker),
                  state.pendingInvitation == nil || c.invitation==state.pendingInvitation?.id else { throw ConnectError.invalid("Pairing approval changed identity.") }
            peer=c.maker
        }
        if let existing=state.peers.first(where:{$0.id==peer.id}),!existing.sameKeys(peer) { throw ConnectError.invalid("A paired Mac changed its keys. Pair it again explicitly.") }
        var next=state
        if !next.peers.contains(where:{$0.id==peer.id}) { next.peers.append(peer) }
        next.trusted=true; next.pendingInvitation=nil; try commit(next)
    }
    private func updateStatus() async throws {
        let result=try await service.call("status"); status=result["status"] as? String ?? "unregistered"
        for c in result["certificates"] as? [[String:Any]] ?? [] { try apply(typed(PairCertificate.self,c)) }
        pending=try typed([PendingPair].self,result["invitations"] ?? [])
        let listed=try typed([DevicePublic].self,result["devices"] ?? [])
        activePeers=state.peers.filter { known in listed.contains(where:{$0.status=="trusted" && $0.sameKeys(known)}) }
        if status=="trusted" && !state.trusted { throw ConnectError.invalid("This Mac still needs a verified pairing approval.") }
    }
    public func queue(_ text: String) throws {
        guard state.trusted,status=="trusted",let peer=activePeers.first else { throw ConnectError.invalid("Pair and approve the other Mac first.") }
        guard state.outbox.isEmpty else { throw ConnectError.invalid("Your previous edit is queued. Sync it or resolve its conflict first.") }
        var next=state; next.outbox=[QueuedNote(envelope:try .seal(text:text,owner:owner,keys:keys,peer:peer,parent:state.revision),text:text)]
        try commit(next)
    }
    public func sync() async throws {
        guard !busy else { return }; busy=true; defer { busy=false }
        if state.pendingInvitation != nil {
            let info=try await inspect()
            if info["status"] as? String=="unregistered" {
                var next=state; next.pendingInvitation=nil; try commit(next); status="unregistered"; return
            }
        }
        try await updateStatus(); guard status=="trusted",state.trusted else { return }
        if let item=state.outbox.first,!state.conflict {
            let result=try await service.call("publish",["envelope":try object(item.envelope)])
            var next=state
            if result["accepted"] as? Bool == true { next.revision=item.envelope.revision; next.text=item.text; next.outbox.removeFirst() }
            else if result["conflict"] as? Bool == true { next.conflict=true }
            else { throw ConnectError.invalid("Update was not accepted. Your edit is still saved locally.") }
            try commit(next)
        }
        let result=try await service.call("pull",["after":state.cursor])
        for row in result["messages"] as? [[String:Any]] ?? [] {
            guard let cursor=row["cursor"] as? Int64,cursor>state.cursor,let env=row["envelope"] else { throw ConnectError.invalid("Invalid sync cursor.") }
            let note=try typed(EncryptedNote.self,env)
            guard let peer=activePeers.first(where:{$0.id==note.sender}) else { throw ConnectError.invalid("Update from an unverified or removed Mac was held.") }
            let text=try note.open(owner:owner,keys:keys,peer:peer)
            var next=state; next.cursor=cursor; next.text=text; next.revision=note.revision; try commit(next)
        }
    }
    public func useRemote() throws {
        guard !busy else { throw ConnectError.invalid("Wait for the current sync before resolving this edit.") }
        var next=state; next.outbox=[]; next.conflict=false; try commit(next)
    }
    public func keepDraft() throws {
        guard !busy else { throw ConnectError.invalid("Wait for the current sync before resolving this edit.") }
        guard let old=state.outbox.first,let peer=activePeers.first else { throw ConnectError.invalid("No local draft to resolve.") }
        var next=state; next.conflict=false
        next.outbox=[QueuedNote(envelope:try .seal(text:old.text,owner:owner,keys:keys,peer:peer,parent:state.revision),text:old.text)]; try commit(next)
    }
    public func revoke(_ device: DevicePublic) async throws { _=try await service.call("revoke",["device":device.id]); try await updateStatus() }
}
