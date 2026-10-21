import SwiftUI
import AppKit
import Auth
import ConnectCore

@MainActor final class Model: ObservableObject {
    @Published var email=""; @Published var message="Sign in on each Mac, then approve the pairing."
    @Published var signedIn=false; @Published var status=""; @Published var busy=false; @Published var paused=false
    @Published var syncing=false
    @Published var hasTrusted=false; @Published var snapshot: ConnectSnapshot?; @Published var invitation=""
    @Published var comparisons=[String:String]()
    @Published var pastedInvitation=""; @Published var draft=""; @Published var comparison=""; @Published var account=""
    var draftEdited=false
    @Published var lastSync: Date?; @Published var error=false
    var auth: AuthClient?; var engine: ConnectEngine?; var configuration: ServiceConfiguration?
    private var poll: Task<Void,Never>?; private var generation=0
    init() {
        do {
            guard let url=Bundle.main.url(forResource:"Service",withExtension:"json") else { throw ConnectError.invalid("Service configuration is missing from this local build.") }
            let raw=try JSONDecoder().decode(ServiceConfiguration.self,from:Data(contentsOf:url))
            let c=try ServiceConfiguration(url:raw.url,publishableKey:raw.publishableKey); configuration=c
            let a=AuthClient(url:c.url.appendingPathComponent("auth/v1"),headers:["apikey":c.publishableKey],flowType:.pkce,
                             redirectToURL:URL(string:"cafe.nero.connect://auth-callback"),storageKey:"connect.auth.v1",
                             localStorage:DeviceVault(),autoRefreshToken:true)
            auth=a
            Task { if let session=try? await a.session { do { try await attach(session) } catch { fail(error) } } }
        } catch { fail(error) }
    }
    func fail(_ e: Error) {
        if e is CancellationError { return }
        message=(e as? LocalizedError)?.errorDescription ?? "Connect is unavailable. Your local data is kept."; error=true
        if case ConnectError.service(let text,403)=e, text=="Device is not approved." { status="revoked"; setPaused(true) }
    }
    func run(_ action: @escaping () async throws -> Void) {
        guard !busy else { return }; busy=true; error=false
        Task { defer { busy=false }; do { try await action() } catch { fail(error) } }
    }
    func sendLink() { run { [self] in
        guard let auth,!email.trimmingCharacters(in:.whitespaces).isEmpty else { return }
        try await auth.signInWithOTP(email:email.trimmingCharacters(in:.whitespaces),redirectTo:URL(string:"cafe.nero.connect://auth-callback"),shouldCreateUser:true)
        message="Open the sign-in email on this Mac. The link expires in five minutes."
    } }
    func callback(_ url: URL) {
        guard SignInCallback.accepts(url) else { return }
        run { [self] in guard let auth else { return }; let session=try await auth.session(from:url); try await attach(session) }
    }
    func attach(_ session: Session) async throws {
        guard let configuration,let auth else { return }; generation+=1; let current=generation
        poll?.cancel(); poll=nil; engine=nil; snapshot=nil; draft=""; invitation=""; comparison=""
        account=session.user.email ?? "Signed in"; let owner=session.user.id.uuidString.lowercased()
        let name=Host.current().localizedName ?? "This Mac"
        let keys=try await Task.detached { try DeviceVault().keys(owner:owner,name:name) }.value
        guard current==generation else { return }
        let service=ConnectService(configuration:configuration,keys:keys) { try await Access(session:auth.session) }
        let dir=try FileManager.default.url(for:.applicationSupportDirectory,in:.userDomainMask,appropriateFor:nil,create:true)
            .appendingPathComponent("cafe.nero.connect/\(owner)/\(keys.id)")
        let disk=ReplicaDisk(url:dir.appendingPathComponent("state.bin"),key:keys.storage)
        let legacy=dir.deletingLastPathComponent().appendingPathComponent("state.bin")
        if !FileManager.default.fileExists(atPath:disk.url.path),FileManager.default.fileExists(atPath:legacy.path),
           let old=try? ReplicaDisk(url:legacy,key:keys.storage).load(owner:owner,device:keys.id) {
            try disk.save(old)
        }
        let e=try ConnectEngine(owner:owner,keys:keys,service:service,disk:disk)
        engine=e; signedIn=true; paused=false
        let check=try await e.inspect(); status=check["status"] as? String ?? "unregistered"; hasTrusted=check["has_trusted"] as? Bool ?? false
        if status=="trusted" || status=="pending" { try await e.bind(); try await refresh() }
        else { message=hasTrusted ? "Paste a pairing code from your trusted Mac." : "Set up this Mac first, then invite your other Mac." }
        startPolling()
    }
    func setPaused(_ value: Bool) {
        paused=value; poll?.cancel(); poll=nil
        if !value { startPolling() }
    }
    private func startPolling() {
        poll?.cancel(); guard signedIn,!paused,engine != nil else { return }; let current=generation
        poll=Task { [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(for:.seconds(4)) } catch { return }
                guard let self,current==self.generation else { return }
                if !self.paused && !self.busy && self.status != "unregistered" {
                    self.syncing=true
                    do { try await self.refresh() } catch { self.fail(error) }
                    self.syncing=false
                }
            }
        }
    }
    func refresh() async throws {
        guard let engine else { return }; let current=generation; try await engine.sync()
        try Task.checkCancellation(); guard current==generation else { return }
        let fresh=await engine.snapshot(); snapshot=fresh; status=fresh.status
        var codes=[String:String](); for p in fresh.pending { codes[p.id]=try await engine.comparison(p) }; comparisons=codes
        if !draftEdited { draft=fresh.state.outbox.first?.text ?? fresh.state.text }
        comparison=try await engine.waitingComparison() ?? ""; lastSync=Date(); error=false
        message = status=="unregistered" ? "Pairing expired. Get a fresh code from your trusted Mac." : status=="pending" ? "Compare the code on both Macs, then approve on the trusted Mac." : fresh.state.conflict ? "Both Macs edited this note. Choose which version to keep." : fresh.state.outbox.isEmpty ? "Up to date · encrypted shared note" : "Your edit is queued on this Mac."
    }
    func firstMac() { run { [self] in try await engine?.bootstrap(); try await refresh() } }
    func invite() { run { [self] in guard let engine else { return }; invitation=try await engine.invite().code(); message="Copy this five-minute pairing code to the other Mac." } }
    func join() { run { [self] in try await engine?.join(pastedInvitation); pastedInvitation=""; try await refresh() } }
    func approve(_ p: PendingPair) { run { [self] in try await engine?.approve(p); invitation=""; try await refresh() } }
    func publish() { run { [self] in try await engine?.queue(draft); draftEdited=false; if !paused { try await refresh() } else { snapshot=await engine?.snapshot(); message="Saved on this Mac; it will send when you reconnect." } } }
    func synchronize() { run { [self] in try await refresh() } }
    func useRemote() { run { [self] in try await engine?.useRemote(); draftEdited=false; draft=await engine?.snapshot().state.text ?? ""; try await refresh() } }
    func keepMine() { run { [self] in try await engine?.keepDraft(); draftEdited=false; try await refresh() } }
    func revoke(_ peer: DevicePublic) { run { [self] in try await engine?.revoke(peer); try await refresh() } }
    func resetPairing() { run { [self] in
        guard let auth else { return }; let session=try await auth.session
        let owner=session.user.id.uuidString.lowercased(),name=Host.current().localizedName ?? "This Mac"
        try await Task.detached { try DeviceVault().replaceKeys(owner:owner,name:name) }.value
        try await attach(session)
    } }
    func signOut() { run { [self] in
        generation+=1; poll?.cancel(); poll=nil
        defer { engine=nil; snapshot=nil; invitation=""; pastedInvitation=""; draft=""; signedIn=false; account="" }
        try await auth?.signOut(scope:.local)
        message="Signed out on this Mac. The other Mac keeps its own session."
    } }
}
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) { NSApp.activate(ignoringOtherApps:true) }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}
@main struct NeroConnectApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model=Model()
    var body: some Scene {
        WindowGroup("Nero Connect") { Content(model:model).onOpenURL { model.callback($0) } }
            .defaultSize(width:720,height:700)
    }
}
struct Content: View {
    @ObservedObject var model: Model
    @State private var remove: DevicePublic?
    @State private var reset=false
    var body: some View {
        ScrollView {
            VStack(alignment:.leading,spacing:20) {
                HStack {
                    Image(systemName:"laptopcomputer.and.ipad").font(.largeTitle).foregroundStyle(.cyan)
                    VStack(alignment:.leading) { Text("Nero Connect").font(.title.bold()); Text("Two Macs. One private workspace.").foregroundStyle(.secondary) }
                    Spacer(); Text("LOCAL PILOT").font(.caption.monospaced()).foregroundStyle(.secondary)
                }
                if !model.signedIn {
                    GroupBox("Sign in") {
                        VStack(alignment:.leading,spacing:12) {
                            Text("Use the same email on both Macs. Each keeps its own sign-in and device keys.")
                            TextField("Email address",text:$model.email).textContentType(.emailAddress)
                            Button("Send sign-in link",action:model.sendLink).buttonStyle(.borderedProminent)
                            Text("Open the email on the Mac that requested it. This Free test service currently delivers only to your Supabase organization’s approved email addresses, with limited sends.").font(.caption).foregroundStyle(.secondary)
                        }.padding(10)
                    }
                } else {
                    HStack { Label(model.account,systemImage:"person.crop.circle"); Spacer(); Button("Sign out",action:model.signOut) }.font(.callout)
                    if model.status=="unregistered" {
                        if !model.hasTrusted { Button("Set up this Mac",action:model.firstMac).buttonStyle(.borderedProminent) }
                        GroupBox("Connect to your trusted Mac") {
                            VStack(alignment:.leading,spacing:10) {
                                Text("On your first Mac, choose Add my other Mac. Paste its NERO1 code here.")
                                TextField("Pairing code",text:$model.pastedInvitation)
                                Button("Request pairing",action:model.join).disabled(model.pastedInvitation.isEmpty)
                            }.padding(10)
                        }
                    } else if model.status=="revoked" {
                        GroupBox("This Mac’s pairing was removed") {
                            VStack(alignment:.leading,spacing:12) {
                                Text("Saved notes stay on this Mac, but future sync is blocked.")
                                Text(model.snapshot?.state.text ?? "").textSelection(.enabled)
                                Button("Pair this Mac again") { reset=true }
                            }.padding(12)
                        }
                    } else if model.status=="pending" {
                        GroupBox("Waiting for the trusted Mac") {
                            VStack(alignment:.leading,spacing:10) { Text("Check that this same code appears on both screens:")
                                Text(model.comparison).font(.title2.monospaced().bold()).textSelection(.enabled)
                                Text("Approve on your first Mac to finish. No shared notes are available before approval.").foregroundStyle(.secondary)
                            }.padding(12)
                        }
                    } else {
                        HStack {
                            Label(model.paused ? "Sync paused" : "Encrypted connection",systemImage:model.paused ? "pause.circle" : "lock.shield")
                            Spacer(); Toggle("Pause sync",isOn:Binding(get:{model.paused},set:{model.setPaused($0)})).toggleStyle(.switch).fixedSize()
                            Button("Sync now",action:model.synchronize).disabled(model.paused)
                        }
                        ForEach(model.snapshot?.pending ?? []) { p in
                            GroupBox("\(p.device.name) wants to connect") {
                                VStack(alignment:.leading,spacing:10) {
                                    Text("Compare this code with the other Mac before approving.")
                                    Text(model.comparisons[p.id] ?? "").font(.title2.monospaced().bold())
                                    Button("Codes match · Approve this Mac") { model.approve(p) }.buttonStyle(.borderedProminent)
                                }.padding(12)
                            }
                        }
                        GroupBox("Your Macs") {
                            VStack(alignment:.leading,spacing:10) {
                                Label("This Mac",systemImage:"laptopcomputer")
                                ForEach(model.snapshot?.activePeers ?? []) { peer in HStack { Label(peer.name,systemImage:"checkmark.shield"); Spacer(); Button("Remove pairing") { remove=peer } } }
                                if (model.snapshot?.activePeers.isEmpty ?? true) { Button("Add my other Mac",action:model.invite) }
                                if !model.invitation.isEmpty { Text("Pairing code · expires in five minutes").font(.caption)
                                    HStack { Text(model.invitation).lineLimit(2).font(.caption.monospaced()).textSelection(.enabled)
                                        Button("Copy code") { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(model.invitation,forType:.string) } }
                                }
                            }.padding(10)
                        }
                        GroupBox("Shared test note") {
                            VStack(alignment:.leading,spacing:10) {
                                TextEditor(text:Binding(get:{model.draft},set:{model.draft=$0; model.draftEdited=true})).font(.body).frame(minHeight:150).scrollContentBackground(.hidden)
                                if model.snapshot?.state.conflict==true {
                                    Text("Other Mac’s version:").font(.headline)
                                    Text(model.snapshot?.state.text ?? "").textSelection(.enabled)
                                    HStack { Button("Use other Mac’s version",action:model.useRemote); Button("Keep my draft",action:model.keepMine) }
                                } else {
                                    HStack { Button("Share note",action:model.publish).buttonStyle(.borderedProminent)
                                        .disabled((model.snapshot?.activePeers.isEmpty ?? true) || !(model.snapshot?.state.outbox.isEmpty ?? true))
                                        if !(model.snapshot?.state.outbox.isEmpty ?? true) { Label("Queued locally",systemImage:"tray.and.arrow.up") }
                                        if !(model.snapshot?.state.outbox.isEmpty ?? true) { Button("Discard queued edit",action:model.useRemote) }
                                    }
                                }
                                Text("Only this note is shared. Calendars, files, recordings and account credentials stay outside this pilot.").font(.caption).foregroundStyle(.secondary)
                            }.padding(10)
                        }
                    }
                }
                HStack(alignment:.top) {
                    if model.busy || model.syncing { ProgressView().controlSize(.small) }
                    Text(model.message).foregroundStyle(model.error ? Color.orange : Color.secondary).textSelection(.enabled)
                }.font(.callout)
            }.padding(26).disabled(model.busy)
        }.background(.ultraThinMaterial).frame(minWidth:600,minHeight:540)
            .confirmationDialog("Remove this pairing?",isPresented:Binding(get:{remove != nil},set:{if !$0 { remove=nil }})) {
                Button("Remove pairing",role:.destructive) { if let p=remove { model.revoke(p) }; remove=nil }
            } message: { Text("Future sync from that Mac will be refused. Already saved notes remain on it.") }
            .confirmationDialog("Create a new pairing identity?",isPresented:$reset) {
                Button("Create new keys and pair again") { model.resetPairing() }
            } message: { Text("A trusted Mac must approve again. Old cached notes and their retired keys remain stored locally.") }
    }
}
