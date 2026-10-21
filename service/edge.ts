// Signed, bounded Connect admission. No logging of tokens, names or payloads.
const origin = Deno.env.get('SUPABASE_URL')!;
const service = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const publicKey = Deno.env.get('SUPABASE_ANON_KEY')!;
const encoder = new TextEncoder();
const hex = (bytes: ArrayBuffer | Uint8Array) => [...new Uint8Array(bytes)].map(x=>x.toString(16).padStart(2,'0')).join('');
const unhex = (s: string) => { if(!/^(?:[0-9a-f]{2})+$/.test(s)) throw Error(); return Uint8Array.from(s.match(/../g)!.map(x=>parseInt(x,16))); };
const digest = async (s: string) => hex(await crypto.subtle.digest('SHA-256',encoder.encode(s)));
const uuid = (s: unknown) => typeof s==='string' && /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(s);
const response = (status: number,data: unknown) => new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store'}});
async function upstream(path: string, init: RequestInit) { return fetch(origin+path,{...init,redirect:'error',signal:AbortSignal.timeout(12000)}); }
async function rpc(name: string, body: unknown) {
 const r=await upstream('/rest/v1/rpc/'+name,{method:'POST',headers:{apikey:service,Authorization:'Bearer '+service,'Content-Type':'application/json'},body:JSON.stringify(body)});
 const data=await r.json(); return {ok:r.ok,status:r.status,data};
}
async function verify(key: string,signature: string,text: string) {
 if(key?.length!==64 || signature?.length!==128) return false;
 const k=await crypto.subtle.importKey('raw',unhex(key),{name:'Ed25519'},false,['verify']);
 return crypto.subtle.verify('Ed25519',k,unhex(signature),encoder.encode(text));
}
function identity(x: any) { return `${x.id}\n${x.signing}\n${x.encryption}`; }
function certificateText(c: any) { return `nero-connect/approval/1\n${c.owner}\n${c.invitation}\n${identity(c.maker)}\n${identity(c.peer)}`; }
function messageText(m: any) { return `nero-connect/note/1\n${m.owner}\n${m.id}\n${m.sender}\n${m.recipient}\n${m.resource}\n${m.revision}\n${m.parent}\n${m.encapsulated}\n${m.ciphertext}`; }
Deno.serve(async req=>{
 if(req.method!=='POST') return response(405,{error:'POST required'});
 try {
  if(Number(req.headers.get('Content-Length')??0)>65536) return response(413,{error:'Request too large'});
  const text=await req.text(); if(encoder.encode(text).length>65536) return response(413,{error:'Request too large'});
  const packet=JSON.parse(text), authorization=req.headers.get('Authorization');
  if(!authorization?.startsWith('Bearer ')) return response(401,{error:'Sign in first.'});
  const auth=await upstream('/auth/v1/user',{headers:{apikey:publicKey,Authorization:authorization}});
  if(!auth.ok) return response(401,{error:'Sign in again.'});
  const user=await auth.json();
  if(user.is_anonymous || !user.email_confirmed_at) return response(403,{error:'Verify your email before pairing.'});
  const token=authorization.slice(7).split('.')[1];
  const claims=JSON.parse(atob(token.replace(/-/g,'+').replace(/_/g,'/')));
  if(!uuid(user.id)||!uuid(claims.session_id)||packet.owner!==user.id||packet.session!==claims.session_id
   ||!uuid(packet.device)||!uuid(packet.nonce)||!Number.isSafeInteger(packet.millis)
   ||Math.abs(Date.now()-packet.millis)>120000||typeof packet.body!=='string'||packet.body.length>40000
   ||!['inspect','bootstrap','join','bind','status','invite','approve','revoke','pull','publish'].includes(packet.action)) return response(403,{error:'Invalid request identity or time.'});
  const body=JSON.parse(packet.body);
  const lookup=await rpc('connect_v1_key',{p_owner:user.id,p_device:packet.device});
  if(!lookup.ok) return response(503,{error:'Device lookup unavailable.'});
  const known=lookup.data;
  const key=known?.signing??(['inspect','bootstrap','join'].includes(packet.action)?body.keys?.signing:null);
  const transcript=`nero-connect/request/1\n${packet.owner}\n${packet.session}\n${packet.device}\n${packet.nonce}\n${packet.millis}\n${packet.action}\n${await digest(packet.body)}`;
  if(!key||!await verify(key,packet.signature,transcript)) return response(403,{error:'Device signature rejected.'});
  if(['bootstrap','join'].includes(packet.action) && (body.keys?.signing!==key||!/^[0-9a-f]{64}$/.test(body.keys?.encryption??''))) return response(400,{error:'Invalid device keys.'});
  if(packet.action==='join') {
   if(!/^[0-9a-f]{64}$/.test(body.secret??'')) return response(403,{error:'Invalid invitation.'});
   body.secret_hash=await digest(body.secret); delete body.secret;
  }
  if(packet.action==='approve') {
   const c=body.certificate;
   if(!c||c.maker?.id!==packet.device||c.maker?.signing!==key||!await verify(key,c.signature,certificateText(c))) return response(403,{error:'Approval signature rejected.'});
  }
  if(packet.action==='publish') {
   const m=body.envelope;
   if(!m||m.sender!==packet.device||m.owner!==user.id||![m.id,m.resource,m.revision,m.recipient].every(uuid)
    ||(m.parent!==''&&!uuid(m.parent))||!/^[0-9a-f]{64}$/.test(m.encapsulated??'')||typeof m.ciphertext!=='string'||m.ciphertext.length>16000
    ||!await verify(key,m.signature,messageText(m))) return response(403,{error:'Message signature rejected.'});
   body.digest=await digest(messageText(m));
  }
  const result=await rpc('connect_v1_admit',{p_owner:user.id,p_session:claims.session_id,p_device:packet.device,p_nonce:packet.nonce,p_millis:packet.millis,p_action:packet.action,p_body:body});
  if(!result.ok) {
   const code=result.data?.code;
   const allowed=['Session ended. Sign in again.','Request expired. Check the Mac clock.','An existing device must approve this Mac.','Device is not approved.','Sign in again on this Mac.','Awaiting approval on the trusted Mac.','Invalid, expired or used pairing code.','This pilot supports two Macs. Remove an old pairing first.','Two Macs are already registered.','Pairing request expired or changed.','Sync history is full. Export and review before continuing.'];
   return response(code==='42501'?403:code==='53300'?429:409,{error:allowed.includes(result.data?.message)?result.data.message:'Connect refused this operation.',code});
  }
  return response(200,result.data);
 } catch { return response(400,{error:'Invalid Connect request.'}); }
});
