-- Optional manual owner installation after unchanged V4 and released canonical audit SQL.
-- Requires an explicitly delegated installer; creates no role or membership and adopts no custody rows.
BEGIN;
SET LOCAL statement_timeout='5s';
SET LOCAL lock_timeout='5s';
DO $$ DECLARE owner_oid OID;role_name TEXT;relation TEXT;BEGIN
 SELECT relowner INTO STRICT owner_oid FROM pg_catalog.pg_class WHERE oid='public.policy'::regclass;
 IF current_user::regrole::oid<>owner_oid OR pg_catalog.getdatabaseencoding()<>'UTF8'
 OR NOT pg_catalog.pg_has_role(session_user,owner_oid,'USAGE') THEN
  RAISE EXCEPTION 'Original delegated policy owner and UTF8 database required' USING ERRCODE='42501';END IF;
 FOREACH role_name IN ARRAY ARRAY['insurance_policy_binding_guard','firefly_audit_guard'] LOOP
  IF NOT pg_catalog.pg_has_role(session_user,role_name,'SET') OR NOT pg_catalog.pg_has_role(session_user,role_name,'USAGE') THEN
   RAISE EXCEPTION 'Explicit installer owner delegation required' USING ERRCODE='42501';END IF;
 END LOOP;
 IF (SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname IN('insurance_policy_binding_guard','firefly_audit_guard','firefly_audit_writer')
  AND NOT rolsuper AND NOT rolbypassrls AND NOT rolinherit AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication
  AND rolcanlogin=(rolname='firefly_audit_writer'))<>3
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE member IN
  (SELECT oid FROM pg_catalog.pg_roles WHERE rolname IN('insurance_policy_binding_guard','firefly_audit_guard','firefly_audit_writer')))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE oid=owner_oid AND
  (rolsuper OR rolbypassrls OR rolinherit OR rolcanlogin OR rolcreatedb OR rolcreaterole OR rolreplication)) THEN
  RAISE EXCEPTION 'Exact restricted separate policy and audit roles required' USING ERRCODE='42501';END IF;
 FOREACH relation IN ARRAY ARRAY['public.policy_party','public.policy_transaction','public.coverage','public.policy_status_history'] LOOP
  IF (SELECT relowner FROM pg_catalog.pg_class WHERE oid=relation::regclass) IS DISTINCT FROM owner_oid THEN
   RAISE EXCEPTION 'Same original policy relation owner required' USING ERRCODE='42501';END IF;
 END LOOP;
 IF owner_oid IN(SELECT oid FROM pg_catalog.pg_roles WHERE rolname IN('insurance_policy_binding_guard','firefly_audit_guard','firefly_audit_writer')) THEN
  RAISE EXCEPTION 'Business and audit owners must remain distinct' USING ERRCODE='42501';END IF;
END $$;
SET LOCAL ROLE firefly_audit_guard;
DO $$ DECLARE expected RECORD;p pg_catalog.pg_proc%ROWTYPE;BEGIN
 FOR expected IN SELECT * FROM (VALUES
  ('firefly_audit_private.context_for(uuid)','8616221035b02a30dc60e2eed36ed0bd4c19c1b6984440a392e5df5e4b1024db',true,'v'),
  ('firefly_audit_private.require_graph(firefly_audit_private.context)','483fd3cf7bad4e224f3e4198c800005f251808bb9825e3075e4c8b05ef5143ec',true,'v'),
  ('firefly_audit_private.canonical_text(text,text)','684092d8d911493f91da50f41988d0b80fe2579107ad0648e30641b70572b5b6',false,'i'),
  ('firefly_audit_private.canonical_record_bytes(firefly_audit.audit_event)','6257272eb2ebe26119e64a0af407d458f9dbd4050ad72681cc7e5f3ec90dc123',false,'i'),
  ('firefly_audit_private.require_record_hash(firefly_audit.audit_event)','9c29ebde6b5a400a93ce044df0b8eb353753cd25afdf3fc4e572aa6240d4834f',false,'i')) v(signature,body_hash,definer,volatility)
 LOOP
  SELECT * INTO p FROM pg_catalog.pg_proc WHERE oid=pg_catalog.to_regprocedure(expected.signature);
  IF NOT FOUND OR (p.proowner=current_user::regrole::oid AND p.prosecdef=expected.definer AND p.provolatile::text=expected.volatility
   AND NOT p.proisstrict AND NOT p.proleakproof AND p.proparallel='u' AND p.pronargdefaults=0
   AND(SELECT lanname FROM pg_catalog.pg_language WHERE oid=p.prolang)='plpgsql'
   AND p.prokind='f' AND p.proconfig=ARRAY['search_path=pg_catalog']::text[]
   AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc,'UTF8')),'hex')=expected.body_hash) IS NOT TRUE
   OR EXISTS(SELECT 1 FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
    WHERE a.grantee<>p.proowner OR a.privilege_type<>'EXECUTE') THEN
   RAISE EXCEPTION 'Exact released canonical audit helper required' USING ERRCODE='42501';END IF;
 END LOOP;
END $$;
GRANT USAGE ON SCHEMA firefly_audit TO insurance_policy_binding_guard;
GRANT REFERENCES(resource_tenant_id,event_id) ON firefly_audit.audit_event TO insurance_policy_binding_guard;
CREATE FUNCTION firefly_audit.policy_binding_write_scope(p_policy UUID,p_event UUID,p_action TEXT) RETURNS VOID
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c firefly_audit_private.context;e firefly_audit.audit_event;
BEGIN
 SELECT * INTO STRICT c FROM firefly_audit_private.context t
 WHERE t.xid=pg_catalog.pg_current_xact_id_if_assigned() AND t.backend_pid=pg_catalog.pg_backend_pid() AND t.db_session_user=session_user
  AND t.service='core-insurance-policies' AND t.resource_type='governed-policy' AND t.resource_id=p_policy;
 c:=firefly_audit_private.context_for(c.nonce);
 PERFORM firefly_audit_private.require_graph(c);
 SELECT * INTO STRICT e FROM firefly_audit.audit_event t WHERE t.resource_tenant_id=c.resource_tenant_id AND t.event_id=c.event_id;
 PERFORM firefly_audit_private.require_record_hash(e);
 IF (c.new_event AND EXISTS(SELECT 1 FROM firefly_audit_private.completion d WHERE d.nonce=c.nonce)
  AND e.outcome='COMPLETED' AND e.actor_staff_realm IS NULL AND e.actor_staff_id IS NULL
  AND e.action IN('insurance.sandbox.policy.bind','insurance.sandbox.policy.activate')
  AND(p_event IS NULL OR e.event_id=p_event) AND(p_action IS NULL OR e.action=p_action)) IS NOT TRUE THEN
  RAISE EXCEPTION 'Original completed new policy append required' USING ERRCODE='23514';END IF;
 PERFORM firefly_audit_private.context_for(c.nonce);
END $$;
CREATE FUNCTION firefly_audit.policy_binding_event(p_tenant UUID,p_policy UUID,p_event UUID,p_action TEXT,p_digest TEXT,
 p_issuer TEXT,p_subject TEXT,p_client TEXT,p_platform TEXT,p_revision TEXT,p_process UUID,p_correlation UUID,p_causation UUID,p_hash TEXT)
RETURNS TIMESTAMPTZ LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE e firefly_audit.audit_event;previous firefly_audit.audit_event;
BEGIN
 SELECT * INTO STRICT e FROM firefly_audit.audit_event a WHERE a.resource_tenant_id=p_tenant AND a.event_id=p_event;
 PERFORM firefly_audit_private.require_record_hash(e);
 IF p_action='insurance.sandbox.policy.bind' THEN
  IF e.sequence<>1 OR e.previous_hash<>repeat('0',64) OR e.causation_id IS NOT NULL THEN
   RAISE EXCEPTION 'Original policy stream genesis required' USING ERRCODE='23514';END IF;
 ELSIF p_action='insurance.sandbox.policy.activate' THEN
  SELECT * INTO STRICT previous FROM firefly_audit.audit_event a WHERE a.resource_tenant_id=p_tenant AND a.event_id=p_causation;
  PERFORM firefly_audit_private.require_record_hash(previous);
  IF e.sequence<>2 OR previous.sequence<>1 OR e.previous_hash IS DISTINCT FROM previous.record_hash
   OR ROW(previous.service,previous.resource_type,previous.resource_id,previous.action,previous.outcome,previous.actor_issuer,previous.actor_subject)
    IS DISTINCT FROM ROW('core-insurance-policies'::text,'governed-policy'::text,p_policy,'insurance.sandbox.policy.bind'::text,'COMPLETED'::text,p_issuer,p_subject) THEN
   RAISE EXCEPTION 'Exact canonical original policy predecessor required' USING ERRCODE='23514';END IF;
 END IF;
 IF ROW(e.service,e.resource_type,e.resource_id,e.action,e.outcome,e.actor_issuer,e.actor_subject,e.actor_client_id,
  e.actor_platform_tenant_id,e.actor_staff_realm,e.actor_staff_id,e.policy_revision,e.evidence_digest,e.process_id,e.correlation_id,e.causation_id,e.record_hash)
 IS DISTINCT FROM ROW('core-insurance-policies'::text,'governed-policy'::text,p_policy,p_action,'COMPLETED'::text,p_issuer,p_subject,p_client,
  p_platform,NULL::text,NULL::uuid,p_revision,p_digest,p_process,p_correlation,p_causation,p_hash)
 OR p_action NOT IN('insurance.sandbox.policy.bind','insurance.sandbox.policy.activate')
 OR NOT EXISTS(SELECT 1 FROM firefly_audit.audit_outbox o WHERE o.resource_tenant_id=e.resource_tenant_id AND o.event_id=e.event_id
  AND o.service=e.service AND o.resource_type=e.resource_type AND o.resource_id=e.resource_id AND o.sequence=e.sequence AND o.record_hash=e.record_hash AND o.intent='AUDIT_EXPORT')
 OR NOT EXISTS(SELECT 1 FROM firefly_audit.audit_head h WHERE h.resource_tenant_id=e.resource_tenant_id AND h.service=e.service
  AND h.resource_type=e.resource_type AND h.resource_id=e.resource_id AND h.last_sequence>=e.sequence AND(h.last_sequence<>e.sequence OR h.last_hash=e.record_hash))
 OR e.recorded_nanos%1000<>0 THEN
  RAISE EXCEPTION 'Exact canonical permanent policy event required' USING ERRCODE='23514';END IF;
 -- Historical validation does not create/reopen an audit context or grant new mutation authority.
 RETURN TIMESTAMPTZ 'epoch'+e.recorded_seconds*INTERVAL '1 second'+(e.recorded_nanos/1000)*INTERVAL '1 microsecond';
END $$;
REVOKE ALL ON FUNCTION firefly_audit.policy_binding_write_scope(UUID,UUID,TEXT),
 firefly_audit.policy_binding_event(UUID,UUID,UUID,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,UUID,UUID,UUID,TEXT)
 FROM PUBLIC,firefly_audit_writer,firefly_audit_reader;
GRANT EXECUTE ON FUNCTION firefly_audit.policy_binding_write_scope(UUID,UUID,TEXT),
 firefly_audit.policy_binding_event(UUID,UUID,UUID,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,UUID,UUID,UUID,TEXT) TO insurance_policy_binding_guard;
RESET ROLE;
SET LOCAL ROLE insurance_policy_binding_guard;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM insurance_policy_binding.binding) OR EXISTS(SELECT 1 FROM insurance_policy_binding.operation)
 OR EXISTS(SELECT 1 FROM insurance_policy_binding.receipt)
 OR(SELECT count(*) FROM pg_catalog.pg_proc WHERE pronamespace='insurance_policy_binding_private'::regnamespace)<>1 THEN
  RAISE EXCEPTION 'Fresh unactivated V4 custody required; unknown rows and partial installers are not adopted' USING ERRCODE='42501';END IF;
 IF (SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc
  WHERE oid='insurance_policy_binding_private.reject_mutation()'::regprocedure) IS DISTINCT FROM
  'c47e60435290c6e58b9c1af99be2824bb3b72d412093aded606ac48c5d39314a' THEN
  RAISE EXCEPTION 'Original V4 immutable guard required' USING ERRCODE='42501';END IF;
END $$;
CREATE UNIQUE INDEX policy_one_operation_per_phase ON insurance_policy_binding.operation(tenant_id,policy_id,operation);
ALTER TABLE insurance_policy_binding.operation ADD CONSTRAINT policy_operation_audit_fk FOREIGN KEY(tenant_id,event_id)
 REFERENCES firefly_audit.audit_event(resource_tenant_id,event_id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE insurance_policy_binding.receipt ADD CONSTRAINT policy_receipt_audit_fk FOREIGN KEY(tenant_id,event_id)
 REFERENCES firefly_audit.audit_event(resource_tenant_id,event_id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE insurance_policy_binding.binding ADD CONSTRAINT policy_bound_audit_fk FOREIGN KEY(tenant_id,bound_event_id)
 REFERENCES firefly_audit.audit_event(resource_tenant_id,event_id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE insurance_policy_binding.binding ADD CONSTRAINT policy_active_audit_fk FOREIGN KEY(tenant_id,active_event_id)
 REFERENCES firefly_audit.audit_event(resource_tenant_id,event_id) DEFERRABLE INITIALLY DEFERRED;
CREATE FUNCTION insurance_policy_binding_private.hash_fields(VARIADIC fields TEXT[]) RETURNS TEXT
LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE field TEXT;bytes BYTEA;encoded BYTEA:=''::bytea;idx INTEGER;point INTEGER;blank BOOLEAN;
BEGIN
 IF fields IS NULL OR cardinality(fields)<1 OR cardinality(fields)>128 THEN RAISE EXCEPTION 'Bounded policy fields required' USING ERRCODE='23514';END IF;
 FOREACH field IN ARRAY fields LOOP
  IF field IS NULL OR octet_length(field) NOT BETWEEN 1 AND 4096 THEN RAISE EXCEPTION 'Exact policy text required' USING ERRCODE='23514';END IF;
  blank:=true;
  FOR idx IN 1..char_length(field) LOOP
   point:=ascii(substr(field,idx,1));
   IF point BETWEEN 0 AND 31 OR point BETWEEN 127 AND 159 THEN RAISE EXCEPTION 'Policy control character refused' USING ERRCODE='23514';END IF;
   IF NOT(point IN(32,5760,8232,8233,8287,12288) OR point BETWEEN 8192 AND 8198 OR point BETWEEN 8200 AND 8202) THEN blank:=false;END IF;
  END LOOP;
  IF blank THEN RAISE EXCEPTION 'Blank policy text refused' USING ERRCODE='23514';END IF;
  bytes:=convert_to(field,'UTF8');encoded:=encoded||int4send(octet_length(bytes))||bytes;
 END LOOP;
 RETURN encode(sha256(encoded),'hex');
END $$;
CREATE FUNCTION insurance_policy_binding_private.money_text(value NUMERIC) RETURNS TEXT
LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF value IS NULL OR value<0 OR value<>trunc(value,2) OR value>999999999999999.99 THEN RAISE EXCEPTION 'Exact stored policy money required' USING ERRCODE='23514';END IF;
 RETURN trunc(value)::text||'.'||lpad((mod(value,1)*100)::integer::text,2,'0');
END $$;
CREATE FUNCTION insurance_policy_binding_private.instant_text(value TIMESTAMPTZ) RETURNS TEXT
LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE micros INTEGER;
BEGIN
 IF value IS NULL OR NOT isfinite(value) OR extract(year FROM value AT TIME ZONE 'UTC') NOT BETWEEN 1 AND 9999 THEN
  RAISE EXCEPTION 'Finite policy instant required' USING ERRCODE='23514';END IF;
 micros:=extract(microseconds FROM value)::bigint%1000000;
 RETURN to_char(value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS')||CASE WHEN micros=0 THEN ''
  WHEN micros%1000=0 THEN '.'||lpad((micros/1000)::text,3,'0') ELSE '.'||lpad(micros::text,6,'0') END||'Z';
END $$;
CREATE FUNCTION insurance_policy_binding_private.quote_digest(b insurance_policy_binding.binding) RETURNS TEXT
LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE fields TEXT[];item RECORD;seen TEXT[]:=ARRAY[]::text[];size INTEGER:=0;
BEGIN
 IF json_typeof(b.coverage_terms_json::json)<>'object' THEN RAISE EXCEPTION 'Exact coverage object required' USING ERRCODE='23514';END IF;
 fields:=ARRAY['CORE_ACCEPTED_QUOTE_SNAPSHOT_V1',b.tenant_id::text,b.submission_id::text,b.party_id::text,b.product_id::text,b.offer_id::text,
  b.offer_version::text,b.accepted_control_generation::text,b.acceptance_action_id::text,b.acceptance_id::text,b.acceptance_intent_digest,b.terms_digest,b.currency,
  insurance_policy_binding_private.money_text(b.base_premium),insurance_policy_binding_private.money_text(b.tax),insurance_policy_binding_private.money_text(b.fees),
  b.product_revision_id::text,b.product_digest,b.risk_digest,b.provider_version,b.rule_set_version,insurance_policy_binding_private.instant_text(b.accepted_at),b.owner_issuer,b.owner_subject];
 FOR item IN SELECT key,value FROM json_each(b.coverage_terms_json::json) ORDER BY key COLLATE pg_catalog."C" LOOP
  IF item.key=ANY(seen) OR octet_length(item.key)>64 OR(item.key COLLATE pg_catalog."C")!~'^[a-z][a-zA-Z0-9._-]{0,63}$'
   OR json_typeof(item.value)<>'string' THEN RAISE EXCEPTION 'Unique typed coverage terms required' USING ERRCODE='23514';END IF;
  seen:=array_append(seen,item.key);size:=size+octet_length(item.key)+octet_length(item.value#>>'{}');
  fields:=array_append(array_append(fields,item.key),item.value#>>'{}');
 END LOOP;
 IF cardinality(seen) NOT BETWEEN 1 AND 32 OR size>32768 THEN RAISE EXCEPTION 'Bounded coverage terms required' USING ERRCODE='23514';END IF;
 RETURN insurance_policy_binding_private.hash_fields(VARIADIC fields);
END $$;
CREATE FUNCTION insurance_policy_binding_private.receipt_state(p_operation UUID) RETURNS TIMESTAMPTZ
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE o insurance_policy_binding.operation;r insurance_policy_binding.receipt;b insurance_policy_binding.binding;j JSON;
 item RECORD;keys TEXT[]:=ARRAY[]::text[];expected_keys TEXT[]:=ARRAY['policyId','policyNumber','policyStatus','bindingVersion','bindingReceiptDigest','acceptanceActionId','acceptanceId','offerId','offerVersion','termsDigest'];
 decision_digest TEXT;business_digest TEXT;paired_digest TEXT;receipt_digest TEXT;expected_intent TEXT;bound_digest TEXT;status TEXT;version BIGINT;causation UUID;recorded TIMESTAMPTZ;
BEGIN
 SELECT * INTO STRICT o FROM insurance_policy_binding.operation WHERE operation_id=p_operation;
 SELECT * INTO STRICT r FROM insurance_policy_binding.receipt WHERE receipt_id=o.receipt_id;
 SELECT * INTO STRICT b FROM insurance_policy_binding.binding WHERE policy_id=o.policy_id;
 IF ROW(o.tenant_id,o.owner_issuer,o.owner_subject,o.policy_id,o.event_id,o.operation_id,o.action_id,o.intent_digest)
  IS DISTINCT FROM ROW(r.tenant_id,r.owner_issuer,r.owner_subject,r.policy_id,r.event_id,r.operation_id,r.action_id,r.intent_digest)
 OR ROW(o.tenant_id,o.owner_issuer,o.owner_subject) IS DISTINCT FROM ROW(b.tenant_id,b.owner_issuer,b.owner_subject)
 OR b.quote_snapshot_digest IS DISTINCT FROM insurance_policy_binding_private.quote_digest(b) THEN
  RAISE EXCEPTION 'Exact policy custody tuple required' USING ERRCODE='23514';END IF;
 IF o.operation='BIND' THEN status:='BOUND';version:=1;causation:=NULL;
  IF o.event_id IS DISTINCT FROM b.bound_event_id THEN RAISE EXCEPTION 'Original bound event required' USING ERRCODE='23514';END IF;
  expected_intent:=insurance_policy_binding_private.hash_fields('CORE_POLICY_BIND_V1',o.action_id::text,b.submission_id::text,b.party_id::text,b.product_id::text,
   b.offer_id::text,b.offer_version::text,b.accepted_control_generation::text,b.acceptance_action_id::text,b.acceptance_intent_digest,b.terms_digest,
   b.contract_id::text,b.policy_number,to_char(b.inception_date,'YYYY-MM-DD'),to_char(b.expiry_date,'YYYY-MM-DD'));
 ELSIF o.operation='ISSUE' THEN status:='IN_FORCE';version:=2;causation:=b.bound_event_id;
  IF o.event_id IS DISTINCT FROM b.active_event_id OR b.state<>'IN_FORCE' THEN RAISE EXCEPTION 'Exact activation event required' USING ERRCODE='23514';END IF;
  SELECT previous.result_digest INTO STRICT bound_digest FROM insurance_policy_binding.operation bound
   JOIN insurance_policy_binding.receipt previous ON previous.receipt_id=bound.receipt_id
   WHERE bound.tenant_id=o.tenant_id AND bound.policy_id=o.policy_id AND bound.owner_issuer=o.owner_issuer AND bound.owner_subject=o.owner_subject
    AND bound.operation='BIND' AND bound.event_id=b.bound_event_id;
  expected_intent:=insurance_policy_binding_private.hash_fields('CORE_POLICY_ISSUE_V1',o.action_id::text,o.policy_id::text,'1',bound_digest);
 ELSE RAISE EXCEPTION 'Known policy phase required' USING ERRCODE='23514';END IF;
 IF o.intent_digest IS DISTINCT FROM expected_intent THEN RAISE EXCEPTION 'Original phase action intent required' USING ERRCODE='23514';END IF;
 decision_digest:=insurance_policy_binding_private.hash_fields('CORE_POLICY_DECISIONS_V1',o.authorization_policy_revision,o.authorization_decision_id,o.admission_policy_revision,o.admission_decision_id);
 business_digest:=insurance_policy_binding_private.hash_fields(CASE WHEN o.operation='BIND' THEN 'CORE_POLICY_BIND_EFFECT_V1' ELSE 'CORE_POLICY_ACTIVATE_EFFECT_V1' END,
  o.tenant_id::text,o.intent_digest,b.quote_snapshot_digest);
 paired_digest:=insurance_policy_binding_private.hash_fields('CORE_POLICY_PAIRED_EFFECT_V1',business_digest,o.configuration_binding_id::text,o.configuration_binding_version::text,o.configuration_binding_digest,decision_digest);
 IF o.decision_evidence_digest IS DISTINCT FROM decision_digest OR o.evidence_digest IS DISTINCT FROM paired_digest THEN
  RAISE EXCEPTION 'Original two-role policy evidence required' USING ERRCODE='23514';END IF;
 recorded:=firefly_audit.policy_binding_event(o.tenant_id,o.policy_id,o.event_id,
  CASE WHEN o.operation='BIND' THEN 'insurance.sandbox.policy.bind' ELSE 'insurance.sandbox.policy.activate' END,paired_digest,
  o.owner_issuer,o.owner_subject,o.owner_client_id,o.owner_platform_tenant,o.admission_policy_revision,o.process_id,o.correlation_id,causation,r.event_record_hash);
 receipt_digest:=insurance_policy_binding_private.hash_fields('CORE_POLICY_RECEIPT_V1',o.tenant_id::text,o.owner_issuer,o.owner_subject,o.action_id::text,o.intent_digest,
  o.policy_id::text,status,version::text,b.acceptance_id::text,b.terms_digest,r.event_record_hash);
 j:=r.result_json::json;
 IF json_typeof(j)<>'object' THEN RAISE EXCEPTION 'Exact policy result object required' USING ERRCODE='23514';END IF;
 FOR item IN SELECT key,value FROM json_each(j) LOOP
  IF item.key=ANY(keys) OR NOT(item.key=ANY(expected_keys)) OR json_typeof(item.value) IS DISTINCT FROM
   (CASE WHEN item.key IN('bindingVersion','offerVersion') THEN 'number' ELSE 'string' END) THEN
   RAISE EXCEPTION 'Closed typed immutable policy result required' USING ERRCODE='23514';END IF;
  keys:=array_append(keys,item.key);
 END LOOP;
 IF cardinality(keys)<>10 OR ROW(j->>'policyId',j->>'policyNumber',j->>'policyStatus',(j->>'bindingVersion')::numeric,j->>'bindingReceiptDigest',j->>'acceptanceActionId',j->>'acceptanceId',j->>'offerId',(j->>'offerVersion')::numeric,j->>'termsDigest')
  IS DISTINCT FROM ROW(b.policy_id::text,b.policy_number::text,status,version::numeric,receipt_digest,b.acceptance_action_id::text,b.acceptance_id::text,b.offer_id::text,b.offer_version::numeric,b.terms_digest)
 OR r.result_digest IS DISTINCT FROM receipt_digest OR(b.state=status AND b.binding_receipt_digest IS DISTINCT FROM receipt_digest) THEN
  RAISE EXCEPTION 'Exact historical policy receipt required' USING ERRCODE='23514';END IF;
 RETURN recorded;
END $$;
CREATE FUNCTION insurance_policy_binding_private.binding_state(p_policy UUID) RETURNS VOID
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE b insurance_policy_binding.binding;p public.policy;bound_at TIMESTAMPTZ;active_at TIMESTAMPTZ;bound_op UUID;active_op UUID;phases INTEGER;terms JSONB;
BEGIN
 SELECT * INTO STRICT b FROM insurance_policy_binding.binding WHERE policy_id=p_policy;
 SELECT * INTO STRICT p FROM public.policy WHERE policy_id=p_policy;
 SELECT operation_id INTO STRICT bound_op FROM insurance_policy_binding.operation WHERE tenant_id=b.tenant_id AND policy_id=p_policy AND operation='BIND';
 bound_at:=insurance_policy_binding_private.receipt_state(bound_op);phases:=CASE WHEN b.state='BOUND' AND b.binding_version=1 THEN 1 WHEN b.state='IN_FORCE' AND b.binding_version=2 THEN 2 ELSE 0 END;
 IF phases=2 THEN
  SELECT operation_id INTO STRICT active_op FROM insurance_policy_binding.operation WHERE tenant_id=b.tenant_id AND policy_id=p_policy AND operation='ISSUE';
  active_at:=insurance_policy_binding_private.receipt_state(active_op);
 END IF;
 IF phases=0 OR(SELECT count(*) FROM insurance_policy_binding.operation WHERE policy_id=p_policy)<>phases
 OR(SELECT count(*) FROM insurance_policy_binding.receipt WHERE policy_id=p_policy)<>phases
 OR ROW(p.tenant_id,p.contract_id,p.product_id,p.policy_number,p.line_of_business::text,p.policy_status::text,p.currency,p.inception_date,p.expiry_date,p.created_at,p.updated_at,p.renewal_date)
  IS DISTINCT FROM ROW(b.tenant_id,b.contract_id,b.product_id,b.policy_number,'PROPERTY'::text,b.state,b.currency,b.inception_date,b.expiry_date,bound_at,coalesce(active_at,bound_at),NULL::date) THEN
  RAISE EXCEPTION 'Exact policy phase and master effects required' USING ERRCODE='23514';END IF;
 IF(SELECT count(*) FROM public.policy_party WHERE policy_id=p_policy)<>1 OR NOT EXISTS(SELECT 1 FROM public.policy_party x WHERE x.policy_id=p_policy
  AND x.party_id=b.party_id AND x.role::text='POLICYHOLDER' AND x.active IS TRUE AND x.effective_from=b.inception_date AND x.effective_to=b.expiry_date
  AND x.created_at=bound_at AND x.updated_at=bound_at)
 OR(SELECT count(*) FROM public.policy_transaction WHERE policy_id=p_policy)<>1 OR NOT EXISTS(SELECT 1 FROM public.policy_transaction x
  JOIN insurance_policy_binding.operation o ON o.operation_id=bound_op WHERE x.policy_id=p_policy AND x.transaction_number='NB-'||o.action_id::text
  AND x.transaction_type::text='NEW_BUSINESS' AND x.transaction_status::text='BOUND' AND x.effective_date=b.inception_date AND x.expiry_date=b.expiry_date
  AND x.sequence_number=1 AND x.out_of_sequence IS FALSE AND x.notice_days IS NULL AND x.reason IS NULL AND x.created_at=bound_at AND x.updated_at=bound_at) THEN
  RAISE EXCEPTION 'Exact party and new-business effects required' USING ERRCODE='23514';END IF;
 terms:=b.coverage_terms_json::jsonb;
 IF terms->>'coverageCode' IS DISTINCT FROM 'SANDBOX_PROPERTY_DAMAGE' OR terms->>'coverageStart' IS DISTINCT FROM to_char(b.inception_date,'YYYY-MM-DD')
 OR terms->>'coverageEnd' IS DISTINCT FROM to_char(b.expiry_date,'YYYY-MM-DD') OR NOT(terms?'insuredLimit') OR NOT(terms?'deductible')
 OR(terms->>'insuredLimit')::numeric::text IN('NaN','Infinity','-Infinity') OR(terms->>'deductible')::numeric::text IN('NaN','Infinity','-Infinity')
 OR(terms->>'insuredLimit')::numeric<0 OR(terms->>'deductible')::numeric<0
 OR(SELECT count(*) FROM public.coverage WHERE policy_id=p_policy)<>1 OR NOT EXISTS(SELECT 1 FROM public.coverage x JOIN public.policy_transaction t ON t.policy_transaction_id=x.policy_transaction_id
  WHERE x.policy_id=p_policy AND t.policy_id=p_policy AND x.coverage_code='SANDBOX_PROPERTY_DAMAGE'
  AND x.coverage_name='Illustrative sandbox property record; no carrier coverage issuance' AND x.limit_amount=(terms->>'insuredLimit')::numeric
  AND x.deductible_amount=(terms->>'deductible')::numeric AND x.currency=b.currency AND x.premium_amount=b.base_premium AND x.created_at=bound_at AND x.updated_at=bound_at)
 OR(SELECT count(*) FROM public.policy_status_history WHERE policy_id=p_policy)<>phases
 OR NOT EXISTS(SELECT 1 FROM public.policy_status_history h WHERE h.policy_id=p_policy AND h.policy_status::text='BOUND'
  AND h.status_reason='Governed sandbox policy transition' AND h.changed_at=bound_at AND h.created_at=bound_at AND h.updated_at=bound_at)
 OR(phases=2 AND NOT EXISTS(SELECT 1 FROM public.policy_status_history h WHERE h.policy_id=p_policy AND h.policy_status::text='IN_FORCE'
  AND h.status_reason='Governed sandbox policy transition' AND h.changed_at=active_at AND h.created_at=active_at AND h.updated_at=active_at)) THEN
  RAISE EXCEPTION 'Exact coverage and status history effects required' USING ERRCODE='23514';END IF;
END $$;
CREATE FUNCTION insurance_policy_binding_private.guard_write() RETURNS TRIGGER
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE policy UUID;event UUID;action TEXT;operation TEXT;
BEGIN
 policy:=CASE WHEN TG_OP='DELETE' THEN OLD.policy_id ELSE NEW.policy_id END;
 IF session_user<>'firefly_audit_writer' THEN
  IF TG_TABLE_SCHEMA='public' AND NOT EXISTS(SELECT 1 FROM insurance_policy_binding.binding WHERE policy_id=policy) THEN
   IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
  END IF;
  RAISE EXCEPTION 'Restricted policy writer required' USING ERRCODE='42501';END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Governed policy deletion unsupported' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' THEN
  IF TG_TABLE_SCHEMA='insurance_policy_binding' AND TG_TABLE_NAME='binding' THEN
   IF(OLD.state='BOUND' AND OLD.binding_version=1 AND NEW.state='IN_FORCE' AND NEW.binding_version=2 AND NEW.active_event_id IS NOT NULL
    AND(to_jsonb(NEW)-ARRAY['state','binding_version','binding_receipt_digest','active_event_id'])=(to_jsonb(OLD)-ARRAY['state','binding_version','binding_receipt_digest','active_event_id'])) IS NOT TRUE THEN
    RAISE EXCEPTION 'Exact immutable binding compare-and-set required' USING ERRCODE='23514';END IF;
   event:=NEW.active_event_id;
  ELSIF TG_TABLE_SCHEMA='public' AND TG_TABLE_NAME='policy' THEN
   IF(OLD.policy_status::text='BOUND' AND NEW.policy_status::text='IN_FORCE'
    AND(to_jsonb(NEW)-ARRAY['policy_status','updated_at'])=(to_jsonb(OLD)-ARRAY['policy_status','updated_at'])) IS NOT TRUE THEN
    RAISE EXCEPTION 'Exact immutable policy compare-and-set required' USING ERRCODE='23514';END IF;
  ELSE RAISE EXCEPTION 'Exact immutable policy compare-and-set transition required' USING ERRCODE='23514';END IF;
  action:='insurance.sandbox.policy.activate';
 ELSE
  action:='insurance.sandbox.policy.bind';
  IF TG_TABLE_NAME='operation' THEN operation:=NEW.operation;event:=NEW.event_id;
  ELSIF TG_TABLE_NAME='receipt' THEN SELECT o.operation INTO STRICT operation FROM insurance_policy_binding.operation o WHERE o.operation_id=NEW.operation_id;event:=NEW.event_id;
  ELSIF TG_TABLE_NAME='binding' THEN
   IF(NEW.state='BOUND' AND NEW.binding_version=1 AND NEW.active_event_id IS NULL) IS NOT TRUE THEN
    RAISE EXCEPTION 'New binding must start at its original phase' USING ERRCODE='23514';END IF;
   event:=NEW.bound_event_id;
  ELSIF TG_TABLE_NAME='policy_status_history' THEN
   IF NEW.policy_status::text='IN_FORCE' THEN operation:='ISSUE';END IF;
  END IF;
  IF operation='ISSUE' THEN action:='insurance.sandbox.policy.activate';END IF;
 END IF;
 PERFORM firefly_audit.policy_binding_write_scope(policy,event,action);
 RETURN NEW;
END $$;
CREATE FUNCTION insurance_policy_binding_private.deferred_binding() RETURNS TRIGGER
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_TABLE_SCHEMA='public' AND NOT EXISTS(SELECT 1 FROM insurance_policy_binding.binding WHERE policy_id=NEW.policy_id) AND session_user<>'firefly_audit_writer' THEN RETURN NULL;END IF;
 PERFORM firefly_audit.policy_binding_write_scope(NEW.policy_id,NULL,NULL);
 PERFORM insurance_policy_binding_private.binding_state(NEW.policy_id);
 RETURN NULL;
END $$;
CREATE TABLE insurance_policy_binding_private.protocol_manifest(signature TEXT PRIMARY KEY,function_oid OID UNIQUE NOT NULL,body_hash TEXT NOT NULL CHECK((body_hash~'^[0-9a-f]{64}$') IS TRUE),
 definer BOOLEAN NOT NULL,volatility TEXT NOT NULL,result_type OID NOT NULL);
CREATE FUNCTION insurance_policy_binding_private.protocol_state() RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE expected RECORD;p pg_catalog.pg_proc%ROWTYPE;relation TEXT;policy_guard OID;audit_guard OID;writer OID;original_owner OID;expected_owner OID;column_row RECORD;allowed BOOLEAN;
BEGIN
 SELECT oid INTO STRICT policy_guard FROM pg_catalog.pg_roles WHERE rolname='insurance_policy_binding_guard';
 SELECT oid INTO STRICT audit_guard FROM pg_catalog.pg_roles WHERE rolname='firefly_audit_guard';
 SELECT oid INTO STRICT writer FROM pg_catalog.pg_roles WHERE rolname='firefly_audit_writer';
 SELECT relowner INTO STRICT original_owner FROM pg_catalog.pg_class WHERE oid='public.policy'::regclass;
 IF pg_catalog.getdatabaseencoding()<>'UTF8' OR current_setting('TimeZone') NOT IN('UTC','Etc/UTC') OR original_owner IN(policy_guard,audit_guard,writer)
 OR current_setting('session_replication_role')<>'origin' OR current_setting('row_security')<>'on'
 OR pg_catalog.has_parameter_privilege('firefly_audit_writer','session_replication_role','SET')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE oid IN(policy_guard,audit_guard,writer,original_owner)
  AND(rolsuper OR rolbypassrls OR rolinherit OR rolcreatedb OR rolcreaterole OR rolreplication OR rolcanlogin<>(oid=writer)))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE member IN(policy_guard,audit_guard,writer,original_owner))
 OR pg_catalog.has_schema_privilege('firefly_audit_writer','public','CREATE')
 OR pg_catalog.has_schema_privilege('firefly_audit_writer','firefly_audit_private','USAGE')
 OR pg_catalog.has_schema_privilege('firefly_audit_guard','public','CREATE')
 OR pg_catalog.has_table_privilege('insurance_policy_binding_guard','firefly_audit.audit_event','SELECT')
 OR pg_catalog.has_column_privilege('insurance_policy_binding_guard','firefly_audit.audit_event','resource_tenant_id','REFERENCES')
 OR pg_catalog.has_column_privilege('insurance_policy_binding_guard','firefly_audit.audit_event','event_id','REFERENCES') THEN RETURN false;END IF;
 IF(SELECT nspowner FROM pg_catalog.pg_namespace WHERE nspname='insurance_policy_binding') IS DISTINCT FROM policy_guard
 OR(SELECT nspowner FROM pg_catalog.pg_namespace WHERE nspname='insurance_policy_binding_private') IS DISTINCT FROM policy_guard
 OR(SELECT nspowner FROM pg_catalog.pg_namespace WHERE nspname='firefly_audit') IS DISTINCT FROM audit_guard
 OR(SELECT nspowner FROM pg_catalog.pg_namespace WHERE nspname='firefly_audit_private') IS DISTINCT FROM audit_guard THEN RETURN false;END IF;
 FOREACH relation IN ARRAY ARRAY['firefly_audit.audit_head','firefly_audit.audit_event','firefly_audit.audit_outbox','firefly_audit_private.context','firefly_audit_private.completion'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname=split_part(relation,'.',1) AND c.relname=split_part(relation,'.',2) AND c.relowner=audit_guard AND c.relkind='r'
   AND c.relrowsecurity=(relation LIKE 'firefly_audit.%') AND c.relforcerowsecurity=(relation LIKE 'firefly_audit.%')) THEN RETURN false;END IF;
 END LOOP;
 FOREACH relation IN ARRAY ARRAY['insurance_policy_binding.binding','insurance_policy_binding.operation','insurance_policy_binding.receipt','insurance_policy_binding_private.protocol_manifest',
  'public.policy','public.policy_party','public.policy_transaction','public.coverage','public.policy_status_history'] LOOP
  expected_owner:=CASE WHEN relation LIKE 'public.%' THEN original_owner ELSE policy_guard END;
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=relation::regclass AND relowner=expected_owner AND relkind='r' AND NOT relrowsecurity)
   OR EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=relation::regclass AND NOT tgisinternal AND tgenabled<>'O') THEN RETURN false;END IF;
 END LOOP;
 IF(SELECT count(*) FROM pg_catalog.pg_constraint WHERE conrelid IN('insurance_policy_binding.binding'::regclass,'insurance_policy_binding.operation'::regclass,'insurance_policy_binding.receipt'::regclass)
  AND conname IN('policy_operation_audit_fk','policy_receipt_audit_fk','policy_bound_audit_fk','policy_active_audit_fk') AND contype='f' AND convalidated AND condeferrable AND condeferred)<>4
 OR(SELECT count(*) FROM insurance_policy_binding_private.protocol_manifest)<>19
 OR(SELECT count(*) FROM pg_catalog.pg_proc WHERE pronamespace='insurance_policy_binding_private'::regnamespace)<>12 THEN RETURN false;END IF;
 FOR expected IN SELECT * FROM insurance_policy_binding_private.protocol_manifest LOOP
  SELECT * INTO p FROM pg_catalog.pg_proc WHERE oid=expected.function_oid;
  expected_owner:=CASE WHEN expected.signature LIKE 'firefly_audit.%' OR expected.signature LIKE 'firefly_audit_private.%' THEN audit_guard ELSE policy_guard END;
  IF NOT FOUND OR(p.proowner=expected_owner AND p.prokind='f' AND p.prosecdef=expected.definer AND p.provolatile::text=expected.volatility
   AND NOT p.proisstrict AND NOT p.proleakproof AND p.proparallel='u' AND p.pronargdefaults=0 AND NOT p.proretset
   AND(SELECT lanname FROM pg_catalog.pg_language WHERE oid=p.prolang)='plpgsql'
   AND p.provariadic=CASE WHEN expected.signature='insurance_policy_binding_private.hash_fields(text[])' THEN 'pg_catalog.text'::regtype::oid ELSE 0::oid END
   AND p.prorettype=expected.result_type AND p.proconfig=ARRAY['search_path=pg_catalog']::text[]
   AND regexp_replace((SELECT nspname FROM pg_catalog.pg_namespace WHERE oid=p.pronamespace)||'.'||p.proname||'('||pg_catalog.oidvectortypes(p.proargtypes)||')',', ',',','g')=expected.signature
   AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc,'UTF8')),'hex')=expected.body_hash) IS NOT TRUE THEN RETURN false;END IF;
  IF EXISTS(SELECT 1 FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
   WHERE a.privilege_type<>'EXECUTE' OR a.grantee NOT IN(p.proowner,
    CASE WHEN expected.signature LIKE 'firefly_audit.%' THEN policy_guard WHEN expected.signature IN('insurance_policy_binding_private.verify_protocol()','insurance_policy_binding_private.verify_receipt(uuid)') THEN writer ELSE p.proowner END)
    OR(a.grantee<>p.proowner AND a.is_grantable)) THEN RETURN false;END IF;
 END LOOP;
 FOR expected IN SELECT * FROM (VALUES
  ('insurance_policy_binding.binding','tenant_id,policy_id','public.policy','tenant_id,policy_id'),
  ('insurance_policy_binding.operation','tenant_id,policy_id,owner_issuer,owner_subject','insurance_policy_binding.binding','tenant_id,policy_id,owner_issuer,owner_subject'),
  ('insurance_policy_binding.operation','tenant_id,receipt_id','insurance_policy_binding.receipt','tenant_id,receipt_id'),
  ('insurance_policy_binding.receipt','tenant_id,operation_id,action_id,intent_digest,policy_id,event_id','insurance_policy_binding.operation','tenant_id,operation_id,action_id,intent_digest,policy_id,event_id'),
  ('insurance_policy_binding.receipt','tenant_id,policy_id,owner_issuer,owner_subject','insurance_policy_binding.binding','tenant_id,policy_id,owner_issuer,owner_subject'),
  ('insurance_policy_binding.operation','tenant_id,event_id','firefly_audit.audit_event','resource_tenant_id,event_id'),
  ('insurance_policy_binding.receipt','tenant_id,event_id','firefly_audit.audit_event','resource_tenant_id,event_id'),
  ('insurance_policy_binding.binding','tenant_id,bound_event_id','firefly_audit.audit_event','resource_tenant_id,event_id'),
  ('insurance_policy_binding.binding','tenant_id,active_event_id','firefly_audit.audit_event','resource_tenant_id,event_id')) v(relation,local_columns,target,target_columns)
 LOOP
  IF(SELECT count(*) FROM pg_catalog.pg_constraint c WHERE c.contype='f' AND c.conrelid=expected.relation::regclass AND c.confrelid=expected.target::regclass
   AND c.conkey=ARRAY(SELECT(SELECT attnum FROM pg_catalog.pg_attribute WHERE attrelid=c.conrelid AND attname=x AND attnum>0 AND NOT attisdropped)
    FROM unnest(string_to_array(expected.local_columns,',')) x)
   AND c.confkey=ARRAY(SELECT(SELECT attnum FROM pg_catalog.pg_attribute WHERE attrelid=c.confrelid AND attname=x AND attnum>0 AND NOT attisdropped)
    FROM unnest(string_to_array(expected.target_columns,',')) x)
   AND c.convalidated AND c.condeferrable AND c.condeferred AND c.confmatchtype='s' AND c.confupdtype='a' AND c.confdeltype='a')<>1 THEN RETURN false;END IF;
 END LOOP;
 FOR expected IN SELECT * FROM (VALUES
  ('insurance_policy_binding.operation','policy_operation_immutable','reject_mutation',27,false),
  ('insurance_policy_binding.receipt','policy_receipt_immutable','reject_mutation',27,false),
  ('insurance_policy_binding_private.protocol_manifest','policy_protocol_manifest_immutable','reject_mutation',31,false),
  ('public.policy','governed_policy_write','guard_write',31,false),('public.policy_party','governed_policy_party_write','guard_write',31,false),
  ('public.policy_transaction','governed_policy_transaction_write','guard_write',31,false),('public.coverage','governed_policy_coverage_write','guard_write',31,false),
  ('public.policy_status_history','governed_policy_history_write','guard_write',31,false),
  ('public.policy','governed_policy_graph','deferred_binding',21,true),('public.policy_party','governed_policy_party_graph','deferred_binding',21,true),
  ('public.policy_transaction','governed_policy_transaction_graph','deferred_binding',21,true),('public.coverage','governed_policy_coverage_graph','deferred_binding',21,true),
  ('public.policy_status_history','governed_policy_history_graph','deferred_binding',21,true),
  ('insurance_policy_binding.binding','governed_binding_write','guard_write',31,false),
  ('insurance_policy_binding.operation','governed_operation_write','guard_write',7,false),('insurance_policy_binding.receipt','governed_receipt_write','guard_write',7,false),
  ('insurance_policy_binding.binding','governed_binding_graph','deferred_binding',21,true),
  ('insurance_policy_binding.operation','governed_operation_graph','deferred_binding',5,true),('insurance_policy_binding.receipt','governed_receipt_graph','deferred_binding',5,true)) v(relation,name,function_name,type_bits,deferred)
 LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc f ON f.oid=t.tgfoid JOIN pg_catalog.pg_namespace n ON n.oid=f.pronamespace
   WHERE t.tgrelid=expected.relation::regclass AND t.tgname=expected.name AND t.tgtype=expected.type_bits AND NOT t.tgisinternal
    AND t.tgenabled='O' AND t.tgdeferrable=expected.deferred AND t.tginitdeferred=expected.deferred AND t.tgnargs=0 AND t.tgqual IS NULL
    AND n.nspname='insurance_policy_binding_private' AND f.proname=expected.function_name AND f.proowner=policy_guard) THEN RETURN false;END IF;
 END LOOP;
 IF NOT pg_catalog.has_schema_privilege('firefly_audit_writer','insurance_policy_binding','USAGE')
 OR NOT pg_catalog.has_schema_privilege('firefly_audit_writer','insurance_policy_binding_private','USAGE')
 OR pg_catalog.has_schema_privilege('firefly_audit_writer','insurance_policy_binding','CREATE')
 OR pg_catalog.has_schema_privilege('firefly_audit_writer','insurance_policy_binding_private','CREATE')
 OR NOT pg_catalog.has_function_privilege('firefly_audit_writer','insurance_policy_binding_private.verify_protocol()','EXECUTE')
 OR NOT pg_catalog.has_function_privilege('firefly_audit_writer','insurance_policy_binding_private.verify_receipt(uuid)','EXECUTE') THEN RETURN false;END IF;
 FOREACH relation IN ARRAY ARRAY['insurance_policy_binding.binding','insurance_policy_binding.operation','insurance_policy_binding.receipt',
  'public.policy','public.policy_party','public.policy_transaction','public.coverage','public.policy_status_history'] LOOP
  IF NOT pg_catalog.has_table_privilege('firefly_audit_writer',relation,'SELECT') OR NOT pg_catalog.has_table_privilege('firefly_audit_writer',relation,'INSERT')
   OR pg_catalog.has_table_privilege('firefly_audit_writer',relation,'DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN RETURN false;END IF;
  IF EXISTS(SELECT 1 FROM pg_catalog.pg_class c CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(c.relacl,pg_catalog.acldefault('r',c.relowner))) a
   WHERE c.oid=relation::regclass AND(a.grantee=0 OR(a.grantee=writer AND a.is_grantable)
    OR(relation NOT LIKE 'public.%' AND a.grantee NOT IN(policy_guard,writer)))) THEN RETURN false;END IF;
  FOR column_row IN SELECT attname FROM pg_catalog.pg_attribute WHERE attrelid=relation::regclass AND attnum>0 AND NOT attisdropped LOOP
   allowed:=(relation='public.policy' AND column_row.attname IN('policy_status','updated_at'))
    OR(relation='insurance_policy_binding.binding' AND column_row.attname IN('state','binding_version','binding_receipt_digest','active_event_id'));
   IF pg_catalog.has_column_privilege('firefly_audit_writer',relation,column_row.attname,'UPDATE') IS DISTINCT FROM allowed THEN RETURN false;END IF;
   IF EXISTS(SELECT 1 FROM pg_catalog.pg_attribute t CROSS JOIN LATERAL pg_catalog.aclexplode(t.attacl) a
    WHERE t.attrelid=relation::regclass AND t.attname=column_row.attname AND(a.grantee=0 OR(a.grantee=writer AND a.is_grantable))) THEN RETURN false;END IF;
  END LOOP;
 END LOOP;
 RETURN true;
END $$;
CREATE FUNCTION insurance_policy_binding_private.verify_protocol() RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF session_user<>'firefly_audit_writer' OR insurance_policy_binding_private.protocol_state() IS NOT TRUE THEN
  RAISE EXCEPTION 'Exact installed restricted policy protocol required' USING ERRCODE='42501';END IF;
 RETURN true;
END $$;
CREATE FUNCTION insurance_policy_binding_private.verify_receipt(p_operation UUID) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE policy UUID;
BEGIN
 PERFORM insurance_policy_binding_private.verify_protocol();
 IF p_operation IS NULL OR p_operation='00000000-0000-0000-0000-000000000000'::uuid THEN RAISE EXCEPTION 'Exact operation identity required' USING ERRCODE='23514';END IF;
 SELECT policy_id INTO STRICT policy FROM insurance_policy_binding.operation WHERE operation_id=p_operation;
 PERFORM insurance_policy_binding_private.binding_state(policy);
 RETURN true;
END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA insurance_policy_binding_private FROM PUBLIC,firefly_audit_writer,firefly_audit_reader;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA insurance_policy_binding_private FROM PUBLIC,firefly_audit_writer,firefly_audit_reader;
RESET ROLE;
-- The installer inherits the original table owner and guard solely for these manual DDL steps.
CREATE TRIGGER governed_policy_write BEFORE INSERT OR UPDATE OR DELETE ON public.policy FOR EACH ROW EXECUTE FUNCTION insurance_policy_binding_private.guard_write();
CREATE TRIGGER governed_policy_party_write BEFORE INSERT OR UPDATE OR DELETE ON public.policy_party FOR EACH ROW EXECUTE FUNCTION insurance_policy_binding_private.guard_write();
CREATE TRIGGER governed_policy_transaction_write BEFORE INSERT OR UPDATE OR DELETE ON public.policy_transaction FOR EACH ROW EXECUTE FUNCTION insurance_policy_binding_private.guard_write();
CREATE TRIGGER governed_policy_coverage_write BEFORE INSERT OR UPDATE OR DELETE ON public.coverage FOR EACH ROW EXECUTE FUNCTION insurance_policy_binding_private.guard_write();
CREATE TRIGGER governed_policy_history_write BEFORE INSERT OR UPDATE OR DELETE ON public.policy_status_history FOR EACH ROW EXECUTE FUNCTION insurance_policy_binding_private.guard_write();
CREATE CONSTRAINT TRIGGER governed_policy_graph AFTER INSERT OR UPDATE ON public.policy DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION insurance_policy_binding_private.deferred_binding();
CREATE CONSTRAINT TRIGGER governed_policy_party_graph AFTER INSERT OR UPDATE ON public.policy_party DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION insurance_policy_binding_private.deferred_binding();
CREATE CONSTRAINT TRIGGER governed_policy_transaction_graph AFTER INSERT OR UPDATE ON public.policy_transaction DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION insurance_policy_binding_private.deferred_binding();
CREATE CONSTRAINT TRIGGER governed_policy_coverage_graph AFTER INSERT OR UPDATE ON public.coverage DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION insurance_policy_binding_private.deferred_binding();
CREATE CONSTRAINT TRIGGER governed_policy_history_graph AFTER INSERT OR UPDATE ON public.policy_status_history DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION insurance_policy_binding_private.deferred_binding();
SET LOCAL ROLE insurance_policy_binding_guard;
CREATE TRIGGER governed_binding_write BEFORE INSERT OR UPDATE OR DELETE ON insurance_policy_binding.binding FOR EACH ROW EXECUTE FUNCTION insurance_policy_binding_private.guard_write();
CREATE TRIGGER governed_operation_write BEFORE INSERT ON insurance_policy_binding.operation FOR EACH ROW EXECUTE FUNCTION insurance_policy_binding_private.guard_write();
CREATE TRIGGER governed_receipt_write BEFORE INSERT ON insurance_policy_binding.receipt FOR EACH ROW EXECUTE FUNCTION insurance_policy_binding_private.guard_write();
CREATE CONSTRAINT TRIGGER governed_binding_graph AFTER INSERT OR UPDATE ON insurance_policy_binding.binding DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION insurance_policy_binding_private.deferred_binding();
CREATE CONSTRAINT TRIGGER governed_operation_graph AFTER INSERT ON insurance_policy_binding.operation DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION insurance_policy_binding_private.deferred_binding();
CREATE CONSTRAINT TRIGGER governed_receipt_graph AFTER INSERT ON insurance_policy_binding.receipt DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION insurance_policy_binding_private.deferred_binding();
INSERT INTO insurance_policy_binding_private.protocol_manifest SELECT signature,p.oid,
 pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc,'UTF8')),'hex'),definer,volatility,p.prorettype FROM(VALUES
 ('firefly_audit.policy_binding_write_scope(uuid,uuid,text)',true,'v','pg_catalog.void'),
 ('firefly_audit.policy_binding_event(uuid,uuid,uuid,text,text,text,text,text,text,text,uuid,uuid,uuid,text)',true,'v','pg_catalog.timestamptz'),
 ('insurance_policy_binding_private.hash_fields(text[])',false,'i','pg_catalog.text'),
 ('insurance_policy_binding_private.money_text(numeric)',false,'i','pg_catalog.text'),
 ('insurance_policy_binding_private.instant_text(timestamp with time zone)',false,'s','pg_catalog.text'),
 ('insurance_policy_binding_private.quote_digest(insurance_policy_binding.binding)',false,'s','pg_catalog.text'),
 ('insurance_policy_binding_private.receipt_state(uuid)',true,'v','pg_catalog.timestamptz'),
 ('insurance_policy_binding_private.binding_state(uuid)',true,'v','pg_catalog.void'),
 ('insurance_policy_binding_private.guard_write()',true,'v','pg_catalog.trigger'),
 ('insurance_policy_binding_private.deferred_binding()',true,'v','pg_catalog.trigger'),
 ('insurance_policy_binding_private.protocol_state()',true,'v','pg_catalog.bool'),
 ('insurance_policy_binding_private.verify_protocol()',true,'v','pg_catalog.bool'),
 ('insurance_policy_binding_private.verify_receipt(uuid)',true,'v','pg_catalog.bool'),
 ('insurance_policy_binding_private.reject_mutation()',false,'v','pg_catalog.trigger'),
 ('firefly_audit_private.context_for(uuid)',true,'v','firefly_audit_private.context'),
 ('firefly_audit_private.require_graph(firefly_audit_private.context)',true,'v','pg_catalog.void'),
 ('firefly_audit_private.canonical_text(text,text)',false,'i','pg_catalog.bytea'),
 ('firefly_audit_private.canonical_record_bytes(firefly_audit.audit_event)',false,'i','pg_catalog.bytea'),
 ('firefly_audit_private.require_record_hash(firefly_audit.audit_event)',false,'i','pg_catalog.void')) v(signature,definer,volatility,result_name)
 CROSS JOIN pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE regexp_replace(n.nspname||'.'||p.proname||'('||pg_catalog.oidvectortypes(p.proargtypes)||')',', ',',','g')=signature
 AND pg_catalog.format_type(p.prorettype,NULL)=CASE result_name WHEN 'pg_catalog.timestamptz' THEN 'timestamp with time zone'
  WHEN 'pg_catalog.bool' THEN 'boolean' ELSE replace(result_name,'pg_catalog.','') END;
CREATE TRIGGER policy_protocol_manifest_immutable BEFORE INSERT OR UPDATE OR DELETE ON insurance_policy_binding_private.protocol_manifest
 FOR EACH ROW EXECUTE FUNCTION insurance_policy_binding_private.reject_mutation();
GRANT USAGE ON SCHEMA insurance_policy_binding,insurance_policy_binding_private TO firefly_audit_writer;
GRANT SELECT,INSERT ON insurance_policy_binding.binding,insurance_policy_binding.operation,insurance_policy_binding.receipt TO firefly_audit_writer;
GRANT UPDATE(state,binding_version,binding_receipt_digest,active_event_id) ON insurance_policy_binding.binding TO firefly_audit_writer;
GRANT EXECUTE ON FUNCTION insurance_policy_binding_private.verify_protocol(),insurance_policy_binding_private.verify_receipt(UUID) TO firefly_audit_writer;
RESET ROLE;
GRANT SELECT ON public.policy,public.policy_party,public.policy_transaction,public.coverage,public.policy_status_history TO insurance_policy_binding_guard;
GRANT SELECT,INSERT ON public.policy,public.policy_party,public.policy_transaction,public.coverage,public.policy_status_history TO firefly_audit_writer;
GRANT UPDATE(policy_status,updated_at) ON public.policy TO firefly_audit_writer;
SET LOCAL ROLE firefly_audit_guard;
REVOKE REFERENCES(resource_tenant_id,event_id) ON firefly_audit.audit_event FROM insurance_policy_binding_guard;
RESET ROLE;
SET LOCAL ROLE insurance_policy_binding_guard;
DO $$ BEGIN
 IF insurance_policy_binding_private.protocol_state() IS NOT TRUE THEN RAISE EXCEPTION 'Complete policy integrity deployment required' USING ERRCODE='42501';END IF;
END $$;
RESET ROLE;
COMMIT;
