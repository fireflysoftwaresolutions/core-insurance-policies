-- OPTIONAL OWNER INSTALLER SOURCE. Never included in ordinary db/migration discovery.
-- Requires separately delegated restricted owners and the existing canonical audit roles.
-- No role is created, no existing row is rewritten, and no runtime permission is granted here.
BEGIN;
DO $$
DECLARE owner_oid OID;relation TEXT;
BEGIN
 SELECT relowner INTO STRICT owner_oid FROM pg_catalog.pg_class WHERE oid='public.policy'::pg_catalog.regclass;
 IF owner_oid IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)
 OR NOT pg_catalog.pg_has_role(session_user,'insurance_policy_binding_guard','SET')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE oid=owner_oid AND
    (rolsuper OR rolbypassrls OR rolinherit OR rolcanlogin OR rolcreatedb OR rolcreaterole OR rolreplication))
 OR (SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname='insurance_policy_binding_guard'
    AND NOT rolsuper AND NOT rolbypassrls AND NOT rolinherit AND NOT rolcanlogin
    AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication)<>1
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='insurance_policy_binding_guard'))
 OR pg_catalog.pg_has_role('firefly_audit_writer','insurance_policy_binding_guard','MEMBER') THEN
  RAISE EXCEPTION 'Separately delegated restricted policy owners required' USING ERRCODE='42501';
 END IF;
 FOREACH relation IN ARRAY ARRAY['public.policy_party','public.policy_transaction','public.coverage','public.policy_status_history'] LOOP
  IF (SELECT relowner FROM pg_catalog.pg_class WHERE oid=relation::pg_catalog.regclass) IS DISTINCT FROM owner_oid THEN
   RAISE EXCEPTION 'Exact original policy relation ownership required' USING ERRCODE='42501';
  END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname IN('insurance_policy_binding','insurance_policy_binding_private')) THEN
  RAISE EXCEPTION 'Fresh governed policy schemas required; existing resources are not adopted' USING ERRCODE='42501';
 END IF;
END $$;
CREATE UNIQUE INDEX governed_policy_tenant_identity ON public.policy(tenant_id,policy_id);
GRANT REFERENCES(tenant_id,policy_id) ON public.policy TO insurance_policy_binding_guard;
SET LOCAL ROLE insurance_policy_binding_guard;
CREATE SCHEMA insurance_policy_binding AUTHORIZATION insurance_policy_binding_guard;
CREATE SCHEMA insurance_policy_binding_private AUTHORIZATION insurance_policy_binding_guard;
REVOKE ALL ON SCHEMA insurance_policy_binding,insurance_policy_binding_private FROM PUBLIC,firefly_audit_writer,firefly_audit_reader;
CREATE TABLE insurance_policy_binding.binding(
 policy_id UUID PRIMARY KEY,
 tenant_id UUID NOT NULL,
 owner_issuer TEXT NOT NULL,
 owner_subject TEXT NOT NULL,
 submission_id UUID NOT NULL,
 party_id UUID NOT NULL,
 product_id UUID NOT NULL,
 contract_id UUID NOT NULL,
 policy_number VARCHAR(64) NOT NULL,
 currency VARCHAR(3) NOT NULL CHECK((currency='USD') IS TRUE),
 inception_date DATE NOT NULL,
 expiry_date DATE NOT NULL,
 offer_id UUID NOT NULL,
 offer_version BIGINT NOT NULL CHECK((offer_version>0) IS TRUE),
 accepted_control_generation BIGINT NOT NULL CHECK((accepted_control_generation>0) IS TRUE),
 acceptance_action_id UUID NOT NULL,
 acceptance_id UUID NOT NULL,
 acceptance_intent_digest TEXT NOT NULL CHECK((acceptance_intent_digest~'^[0-9a-f]{64}$') IS TRUE),
 terms_digest TEXT NOT NULL CHECK((terms_digest~'^[0-9a-f]{64}$') IS TRUE),
 accepted_at TIMESTAMPTZ NOT NULL,
 quote_snapshot_digest TEXT NOT NULL CHECK((quote_snapshot_digest~'^[0-9a-f]{64}$') IS TRUE),
 product_revision_id UUID NOT NULL,
 product_digest TEXT NOT NULL CHECK((product_digest~'^[0-9a-f]{64}$') IS TRUE),
 risk_digest TEXT NOT NULL CHECK((risk_digest~'^[0-9a-f]{64}$') IS TRUE),
 provider_version TEXT NOT NULL CHECK((provider_version='firefly-sandbox-property-1') IS TRUE),
 rule_set_version TEXT NOT NULL CHECK((rule_set_version='illustrative-property-1') IS TRUE),
 base_premium NUMERIC(19,4) NOT NULL,
 tax NUMERIC(19,4) NOT NULL,
 fees NUMERIC(19,4) NOT NULL,
 coverage_terms_json TEXT NOT NULL,
 state TEXT NOT NULL,
 binding_version BIGINT NOT NULL,
 binding_receipt_digest TEXT NOT NULL CHECK((binding_receipt_digest~'^[0-9a-f]{64}$') IS TRUE),
 bound_event_id UUID NOT NULL,
 active_event_id UUID NULL,
 UNIQUE(tenant_id,policy_id,owner_issuer,owner_subject),
 UNIQUE(tenant_id,acceptance_id),
 FOREIGN KEY(tenant_id,policy_id) REFERENCES public.policy(tenant_id,policy_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK((inception_date<expiry_date AND inception_date>=DATE '0001-01-01' AND expiry_date<=DATE '9999-12-31') IS TRUE),
 CHECK((base_premium>0 AND tax>=0 AND fees>=0 AND base_premium=pg_catalog.trunc(base_premium,2)
    AND tax=pg_catalog.trunc(tax,2) AND fees=pg_catalog.trunc(fees,2)) IS TRUE),
 CHECK((pg_catalog.octet_length(coverage_terms_json)<=65536 AND pg_catalog.jsonb_typeof(coverage_terms_json::pg_catalog.jsonb)='object') IS TRUE),
 CHECK(((state='BOUND' AND binding_version=1 AND active_event_id IS NULL)
    OR(state='IN_FORCE' AND binding_version=2 AND active_event_id IS NOT NULL)) IS TRUE)
);
CREATE TABLE insurance_policy_binding.operation(
 operation_id UUID PRIMARY KEY,
 tenant_id UUID NOT NULL,
 owner_issuer TEXT NOT NULL,
 owner_subject TEXT NOT NULL,
 owner_client_id TEXT NOT NULL,
 owner_platform_tenant TEXT NOT NULL,
 process_id UUID NOT NULL,
 correlation_id UUID NOT NULL,
 action_id UUID NOT NULL,
 operation TEXT NOT NULL CHECK((operation IN('BIND','ISSUE')) IS TRUE),
 intent_digest TEXT NOT NULL CHECK((intent_digest~'^[0-9a-f]{64}$') IS TRUE),
 policy_id UUID NOT NULL,
 receipt_id UUID NOT NULL,
 event_id UUID NOT NULL,
 evidence_digest TEXT NOT NULL CHECK((evidence_digest~'^[0-9a-f]{64}$') IS TRUE),
 configuration_binding_id UUID NOT NULL,
 configuration_binding_version BIGINT NOT NULL CHECK((configuration_binding_version>0) IS TRUE),
 configuration_binding_digest TEXT NOT NULL CHECK((configuration_binding_digest~'^[0-9a-f]{64}$') IS TRUE),
 authorization_policy_revision TEXT NOT NULL,
 authorization_decision_id TEXT NOT NULL,
 admission_policy_revision TEXT NOT NULL,
 admission_decision_id TEXT NOT NULL,
 decision_evidence_digest TEXT NOT NULL CHECK((decision_evidence_digest~'^[0-9a-f]{64}$') IS TRUE),
 UNIQUE(tenant_id,owner_issuer,owner_subject,action_id),
 UNIQUE(tenant_id,operation_id,action_id,intent_digest,policy_id,event_id),
 FOREIGN KEY(tenant_id,policy_id,owner_issuer,owner_subject)
    REFERENCES insurance_policy_binding.binding(tenant_id,policy_id,owner_issuer,owner_subject) DEFERRABLE INITIALLY DEFERRED,
 CHECK((pg_catalog.octet_length(owner_issuer) BETWEEN 1 AND 512 AND pg_catalog.octet_length(owner_subject) BETWEEN 1 AND 255
    AND pg_catalog.octet_length(owner_client_id) BETWEEN 1 AND 255 AND pg_catalog.octet_length(owner_platform_tenant) BETWEEN 1 AND 255) IS TRUE),
 CHECK((pg_catalog.octet_length(authorization_policy_revision) BETWEEN 1 AND 128 AND pg_catalog.octet_length(admission_policy_revision) BETWEEN 1 AND 128
    AND pg_catalog.octet_length(authorization_decision_id) BETWEEN 1 AND 1024 AND pg_catalog.octet_length(admission_decision_id) BETWEEN 1 AND 1024) IS TRUE)
);
CREATE TABLE insurance_policy_binding.receipt(
 receipt_id UUID PRIMARY KEY,
 tenant_id UUID NOT NULL,
 owner_issuer TEXT NOT NULL,
 owner_subject TEXT NOT NULL,
 operation_id UUID NOT NULL,
 action_id UUID NOT NULL,
 intent_digest TEXT NOT NULL,
 policy_id UUID NOT NULL,
 result_json TEXT NOT NULL,
 result_digest TEXT NOT NULL CHECK((result_digest~'^[0-9a-f]{64}$') IS TRUE),
 event_id UUID NOT NULL,
 event_record_hash TEXT NOT NULL CHECK((event_record_hash~'^[0-9a-f]{64}$') IS TRUE),
 UNIQUE(tenant_id,receipt_id),
 FOREIGN KEY(tenant_id,operation_id,action_id,intent_digest,policy_id,event_id)
    REFERENCES insurance_policy_binding.operation(tenant_id,operation_id,action_id,intent_digest,policy_id,event_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(tenant_id,policy_id,owner_issuer,owner_subject)
    REFERENCES insurance_policy_binding.binding(tenant_id,policy_id,owner_issuer,owner_subject) DEFERRABLE INITIALLY DEFERRED,
 CHECK((pg_catalog.octet_length(result_json)<=65536 AND pg_catalog.jsonb_typeof(result_json::pg_catalog.jsonb)='object') IS TRUE)
);
ALTER TABLE insurance_policy_binding.operation ADD CONSTRAINT policy_operation_receipt_fk
 FOREIGN KEY(tenant_id,receipt_id) REFERENCES insurance_policy_binding.receipt(tenant_id,receipt_id) DEFERRABLE INITIALLY DEFERRED;
CREATE FUNCTION insurance_policy_binding_private.reject_mutation() RETURNS TRIGGER
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'Governed policy custody is insertion only' USING ERRCODE='23514';END;
$$;
REVOKE ALL ON FUNCTION insurance_policy_binding_private.reject_mutation() FROM PUBLIC,firefly_audit_writer,firefly_audit_reader;
CREATE TRIGGER policy_operation_immutable BEFORE UPDATE OR DELETE ON insurance_policy_binding.operation
 FOR EACH ROW EXECUTE FUNCTION insurance_policy_binding_private.reject_mutation();
CREATE TRIGGER policy_receipt_immutable BEFORE UPDATE OR DELETE ON insurance_policy_binding.receipt
 FOR EACH ROW EXECUTE FUNCTION insurance_policy_binding_private.reject_mutation();
REVOKE ALL ON ALL TABLES IN SCHEMA insurance_policy_binding FROM PUBLIC,firefly_audit_writer,firefly_audit_reader;
RESET ROLE;
REVOKE REFERENCES(tenant_id,policy_id) ON public.policy FROM insurance_policy_binding_guard;
COMMIT;
