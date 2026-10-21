-- Versioned follow-up: prevent expired pending registrations from filling the two-device pilot limit.
create or replace function public.connect_v1_admit(p_owner uuid,p_session uuid,p_device uuid,
 p_nonce uuid,p_millis bigint,p_action text,p_body jsonb) returns jsonb
language plpgsql security invoker set search_path='' as $$
declare d connect_private.devices; i connect_private.invites; peer connect_private.devices;
 env jsonb; cert jsonb; keys jsonb; current_rev uuid; old connect_private.messages;
 c bigint; answer jsonb; v_resource uuid; expected uuid; newrev uuid; target uuid;
begin
 if not exists(select 1 from auth.sessions where id=p_session and user_id=p_owner
   and (not_after is null or not_after>clock_timestamp())) then
  raise exception 'Session ended. Sign in again.' using errcode='42501'; end if;
 if abs(extract(epoch from clock_timestamp())*1000-p_millis)>120000 then
  raise exception 'Request expired. Check the Mac clock.' using errcode='22023'; end if;
 if octet_length(p_body::text)>32768 then raise exception 'Request too large'; end if;
 insert into connect_private.accounts(owner_id) values(p_owner) on conflict do nothing;
 perform 1 from connect_private.accounts where owner_id=p_owner for update;
 delete from connect_private.requests where owner_id=p_owner and created_at<now()-interval '10 minutes';
 if (select count(*) from connect_private.requests where owner_id=p_owner and created_at>now()-interval '1 minute')>=180 then
  raise exception 'Slow down and retry shortly.' using errcode='53300'; end if;
 insert into connect_private.requests(owner_id,nonce) values(p_owner,p_nonce);
 -- Pending keys never acquired trust. Expiry retires only those unapproved
 -- registrations; trusted/revoked key tombstones and approvals remain intact.
 delete from connect_private.devices candidate where candidate.owner_id=p_owner and candidate.status='pending'
  and exists(select 1 from connect_private.invites expired where expired.owner_id=p_owner
   and expired.requester=candidate.id and expired.certificate is null and expired.expires_at<=clock_timestamp())
  and not exists(select 1 from connect_private.invites active where active.owner_id=p_owner
   and active.requester=candidate.id and active.certificate is null and active.expires_at>clock_timestamp());
 select * into d from connect_private.devices where owner_id=p_owner and id=p_device;
 if p_action='inspect' then
  return jsonb_build_object('status',coalesce(d.status,'unregistered'),
   'has_trusted',exists(select 1 from connect_private.devices where owner_id=p_owner and status='trusted'));
 end if;
 if p_action='bootstrap' then
  if d.id is not null or exists(select 1 from connect_private.devices where owner_id=p_owner) then
   raise exception 'An existing device must approve this Mac.' using errcode='42501'; end if;
  keys:=p_body->'keys';
  insert into connect_private.devices(owner_id,id,name,signing_key,encryption_key,session_id,status)
   values(p_owner,p_device,p_body->>'name',keys->>'signing',keys->>'encryption',p_session,'trusted');
  return jsonb_build_object('status','trusted');
 end if;
 if p_action='join' then
  select * into i from connect_private.invites where owner_id=p_owner and id=(p_body->>'invite_id')::uuid;
  if i.id is null or i.expires_at<=clock_timestamp() or i.requester is not null
    or i.secret_hash<>p_body->>'secret_hash' then
   raise exception 'Invalid, expired or used pairing code.' using errcode='42501'; end if;
  select * into peer from connect_private.devices where owner_id=p_owner and id=i.maker and status='trusted';
  if peer.id is null or peer.signing_key<>p_body->>'maker_signing' or peer.encryption_key<>p_body->>'maker_encryption'
   then raise exception 'Invitation identity changed.' using errcode='42501'; end if;
  if d.id is not null or (select count(*) from connect_private.devices where owner_id=p_owner and status<>'revoked')>=2 then
   raise exception 'This pilot supports two Macs. Remove an old pairing first.' using errcode='42501'; end if;
  keys:=p_body->'keys';
  insert into connect_private.devices(owner_id,id,name,signing_key,encryption_key,session_id,status)
   values(p_owner,p_device,p_body->>'name',keys->>'signing',keys->>'encryption',p_session,'pending');
  update connect_private.invites set requester=p_device where owner_id=p_owner and id=i.id;
  return jsonb_build_object('status','pending');
 end if;
 if d.id is null or d.status='revoked' then raise exception 'Device is not approved.' using errcode='42501'; end if;
 if p_action='bind' then
  update connect_private.devices set session_id=p_session where owner_id=p_owner and id=p_device;
  return jsonb_build_object('status',d.status);
 end if;
 if d.session_id<>p_session then raise exception 'Sign in again on this Mac.' using errcode='42501'; end if;
 if p_action='status' then
  return jsonb_build_object('status',d.status,'devices',case when d.status='trusted' then
   (select coalesce(jsonb_agg(jsonb_build_object('id',x.id,'name',x.name,'signing',x.signing_key,'encryption',x.encryption_key,'status',x.status)),'[]')
    from connect_private.devices x where x.owner_id=p_owner and x.id<>p_device) else '[]'::jsonb end,
   'invitations',case when d.status='trusted' then
   (select coalesce(jsonb_agg(jsonb_build_object('id',a.id,'expires',extract(epoch from a.expires_at)::bigint,
    'device',jsonb_build_object('id',b.id,'name',b.name,'signing',b.signing_key,'encryption',b.encryption_key))), '[]')
    from connect_private.invites a join connect_private.devices b on b.owner_id=a.owner_id and b.id=a.requester
    where a.owner_id=p_owner and a.maker=p_device and a.expires_at>clock_timestamp() and a.certificate is null and b.status='pending') else '[]'::jsonb end,
   'certificates',(select coalesce(jsonb_agg(certificate),'[]') from connect_private.invites
    where owner_id=p_owner and (maker=p_device or requester=p_device) and certificate is not null));
 end if;
 if d.status<>'trusted' then raise exception 'Awaiting approval on the trusted Mac.' using errcode='42501'; end if;
 if p_action='invite' then
  if (select count(*) from connect_private.devices where owner_id=p_owner and status<>'revoked')>=2 then
   raise exception 'Two Macs are already registered.'; end if;
  if (select count(*) from connect_private.invites where owner_id=p_owner)>=100 then raise exception 'Invitation limit reached.'; end if;
  update connect_private.invites set expires_at=clock_timestamp() where owner_id=p_owner and maker=p_device and certificate is null;
  insert into connect_private.invites(owner_id,id,maker,secret_hash,expires_at)
   values(p_owner,(p_body->>'id')::uuid,p_device,p_body->>'secret_hash',clock_timestamp()+interval '5 minutes');
  return jsonb_build_object('status','invited');
 elsif p_action='approve' then
  select * into i from connect_private.invites where owner_id=p_owner and id=(p_body->>'invite_id')::uuid;
  if i.maker is distinct from p_device or i.requester is null or i.expires_at<=clock_timestamp() or i.certificate is not null then
   raise exception 'Pairing request expired or changed.' using errcode='42501'; end if;
  select * into peer from connect_private.devices where owner_id=p_owner and id=i.requester and status='pending';
  cert:=p_body->'certificate';
  -- Edge verified this exact certificate signature before admission.
  if peer.id is null or cert->>'owner'<>p_owner::text or cert->>'invitation'<>i.id::text
   or cert->'maker'->>'id'<>p_device::text or cert->'maker'->>'signing'<>d.signing_key
   or cert->'maker'->>'encryption'<>d.encryption_key or cert->'peer'->>'id'<>peer.id::text
   or cert->'peer'->>'signing'<>peer.signing_key or cert->'peer'->>'encryption'<>peer.encryption_key then
   raise exception 'Approval keys do not match the request.' using errcode='42501'; end if;
  update connect_private.devices set status='trusted' where owner_id=p_owner and id=peer.id;
  update connect_private.invites set certificate=cert where owner_id=p_owner and id=i.id;
  return jsonb_build_object('status','approved');
 elsif p_action='revoke' then
  target:=(p_body->>'device')::uuid;
  if target=p_device then raise exception 'Use Sign out for this Mac.'; end if;
  update connect_private.devices set status='revoked' where owner_id=p_owner and id=target;
  update connect_private.invites set expires_at=clock_timestamp() where owner_id=p_owner and (maker=target or requester=target);
  return jsonb_build_object('status','revoked');
 elsif p_action='pull' then
  return jsonb_build_object('messages',(select coalesce(jsonb_agg(jsonb_build_object('cursor',s.cursor,'envelope',s.envelope) order by s.cursor),'[]')
   from (select m.cursor,m.envelope from connect_private.messages m
    join connect_private.devices sender on sender.owner_id=m.owner_id and sender.id=m.sender and sender.status='trusted'
    where m.owner_id=p_owner and m.recipient=p_device and m.cursor>coalesce((p_body->>'after')::bigint,0)
    order by m.cursor limit 100) s));
 elsif p_action='publish' then
  env:=p_body->'envelope'; target:=(env->>'recipient')::uuid;
  if env->>'owner'<>p_owner::text or env->>'sender'<>p_device::text or target=p_device or not exists
    (select 1 from connect_private.devices where owner_id=p_owner and id=target and status='trusted') then
   raise exception 'Recipient unavailable.' using errcode='42501'; end if;
  select * into old from connect_private.messages where owner_id=p_owner and id=(env->>'id')::uuid;
  if old.id is not null then
   if old.envelope<>env then raise exception 'Message identity collision.' using errcode='22023'; end if;
   return jsonb_build_object('accepted',true,'duplicate',true,'cursor',old.cursor);
  end if;
  v_resource:=(env->>'resource')::uuid; newrev:=(env->>'revision')::uuid;
  expected:=nullif(env->>'parent','')::uuid;
  select revision into current_rev from connect_private.heads where owner_id=p_owner and resource=v_resource;
  if current_rev is distinct from expected then
   return jsonb_build_object('accepted',false,'conflict',true,'revision',current_rev); end if;
  if (select count(*) from connect_private.messages where owner_id=p_owner)>=1000 then
   raise exception 'Sync history is full. Export and review before continuing.'; end if;
  update connect_private.accounts set next_cursor=next_cursor+1 where owner_id=p_owner returning next_cursor into c;
  insert into connect_private.messages(owner_id,id,sender,recipient,cursor,digest,envelope)
   values(p_owner,(env->>'id')::uuid,p_device,target,c,p_body->>'digest',env);
  insert into connect_private.heads(owner_id,resource,revision) values(p_owner,v_resource,newrev)
   on conflict(owner_id,resource) do update set revision=excluded.revision;
  return jsonb_build_object('accepted',true,'duplicate',false,'cursor',c);
 end if;
 raise exception 'Unknown Connect operation.' using errcode='22023';
end; $$;
revoke all on function public.connect_v1_admit(uuid,uuid,uuid,uuid,bigint,text,jsonb) from public,anon,authenticated;
grant execute on function public.connect_v1_admit(uuid,uuid,uuid,uuid,bigint,text,jsonb) to service_role;
