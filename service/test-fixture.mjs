import {createClient} from '@supabase/supabase-js';
import {spawn,spawnSync} from 'node:child_process';
import {randomUUID,randomBytes,createHash} from 'node:crypto';
import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const report=process.env.CONNECT_REPORT_DIR??resolve(root,'reports');
const ref='smlbxiktqgqxnzohfnup',run=randomUUID(),secrets=new Set(),users=[];
const receipt={run,startedAt:new Date().toISOString(),sampleDataOnly:true,attempts:[],passed:false,cleanup:{},
 nativeSourceHashes:Object.fromEntries(['Sources/ConnectCore/Protocol.swift','Sources/ConnectCore/Service.swift','Sources/ConnectCore/Storage.swift','Sources/ConnectProbe/Main.swift'].map(p=>[p,createHash('sha256').update(readFileSync(resolve(root,p))).digest('hex')])),
 edgeSourceSHA256:createHash('sha256').update(readFileSync(resolve(root,'service/edge.ts'))).digest('hex')};
const clean=value=>{let s=String(value);for(const x of secrets)if(x)s=s.split(x).join('[redacted]');return s.replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,'[jwt]').slice(0,1200)};
function save(){mkdirSync(report,{recursive:true});writeFileSync(resolve(report,`hosted-${run}.json`),JSON.stringify(receipt,null,2)+'\n')}
function okay(r){if(r.error)throw Error(clean(r.error.message));return r.data}
let admin;
try {
 const listing=spawnSync('supabase',['projects','list','-o','json'],{encoding:'utf8',timeout:30000});
 const project=JSON.parse(listing.stdout).find(x=>x.id===ref);
 if(project?.name!=='neronook-connect-test'||project.organization_id!=='nttcjipnikkgptbotsqx')throw Error('Wrong fixture project');
 const raw=spawnSync('supabase',['projects','api-keys','--project-ref',ref,'-o','json'],{encoding:'utf8',timeout:30000});
 const response=JSON.parse(raw.stdout),keys=Array.isArray(response)?response:response.keys;
 const secret=keys.find(k=>k.name==='service_role'&&!k.disabled)?.api_key;
 const publicKey=keys.find(k=>k.type==='publishable'&&!k.disabled)?.api_key;
 if(!secret||!publicKey)throw Error('Scoped project credentials unavailable'); secrets.add(secret);secrets.add(publicKey);
 admin=createClient(`https://${ref}.supabase.co`,secret,{auth:{persistSession:false,autoRefreshToken:false}});
 const logins=[];
 for(const tag of ['owner','foreign']){
  const password=randomBytes(32).toString('base64url');secrets.add(password);
  const email=`connect-pair-${run}-${tag}@example.invalid`;
  const data=okay(await admin.auth.admin.createUser({email,password,email_confirm:true,app_metadata:{nero_connect_pairing_fixture_run:run}}));
  users.push(data.user.id);logins.push({email,password});
 }
 const probe=process.env.CONNECT_PROBE_PATH;
 if(!probe||!probe.startsWith(root+'/.build/'))throw Error('Set CONNECT_PROBE_PATH to this workspace’s built probe');
 receipt.probeBinarySHA256=createHash('sha256').update(readFileSync(probe)).digest('hex');
 const child=spawn(probe,['--fixture'],{cwd:root,stdio:['pipe','pipe','pipe']});
 child.stdin.end(JSON.stringify({configuration:{url:`https://${ref}.supabase.co`,publishableKey:publicKey},owner:logins[0],foreign:logins[1]}));
 let buffer='',stderr='';
 child.stdout.on('data',b=>{buffer+=b;let pos;while((pos=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,pos);buffer=buffer.slice(pos+1);try{const result=JSON.parse(line);receipt.attempts.push(result);save();console.log(JSON.stringify(result));}catch{receipt.outputError='Non-JSON fixture output';child.kill('SIGTERM')}}});
 child.stderr.on('data',b=>{stderr=clean(stderr+b.toString())});
 const code=await new Promise((done,fail)=>{child.on('error',fail);child.on('exit',done)});
 receipt.passed=code===0&&receipt.attempts.some(x=>x.passed===true&&Array.isArray(x.checks));
 if(!receipt.passed)receipt.error=stderr||'Native probe failed; see retained stage receipt';
}catch(e){receipt.error=clean(e.message)}finally{
 if(admin)try{
  const all=okay(await admin.auth.admin.listUsers({page:1,perPage:100})).users;
  const own=all.filter(x=>x.app_metadata?.nero_connect_pairing_fixture_run===run);
  for(const u of own)okay(await admin.auth.admin.deleteUser(u.id));
  const remaining=okay(await admin.auth.admin.listUsers({page:1,perPage:100})).users.filter(x=>x.app_metadata?.nero_connect_pairing_fixture_run===run);
  if(remaining.length)throw Error('Fixture users remain'); receipt.cleanup={deletedSyntheticUsers:own.length,remainingSyntheticUsers:0};
 }catch(e){receipt.cleanup.error=clean(e.message);receipt.passed=false}
 receipt.finishedAt=new Date().toISOString();save();console.log(JSON.stringify({run,passed:receipt.passed,cleanup:receipt.cleanup,error:receipt.error}));
 if(!receipt.passed)process.exitCode=1;
}
