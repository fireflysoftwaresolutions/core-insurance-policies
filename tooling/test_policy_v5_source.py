"""Portable source-contract controls. These do not parse/execute PL/pgSQL or prove PostgreSQL behavior."""
from pathlib import Path
import hashlib
import re
import struct
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SQL = ROOT / 'core-insurance-policies-models/src/main/resources/db/optional/insurance-policy-binding/V5__Governed_Policy_Integrity.sql'
V4 = SQL.with_name('V4__Governed_Policy_Binding.sql')
BASE = '1eb0eda7c3128484e59d5fb83f95dc00dba20842'
PATTERN = re.compile(r'CREATE FUNCTION\s+([a-z_.]+)\([^;]*?\)\s+RETURNS\s+[^;]*?AS \$\$([\s\S]*?)\$\$;')
FUNCTIONS = {
    'firefly_audit.policy_binding_write_scope', 'firefly_audit.policy_binding_event',
    *('insurance_policy_binding_private.' + name for name in ('hash_fields', 'money_text', 'instant_text', 'quote_digest',
      'receipt_state', 'binding_state', 'guard_write', 'deferred_binding', 'protocol_state', 'verify_protocol', 'verify_receipt')),
}


def source():
    metadata = SQL.lstat()
    if not SQL.is_file() or SQL.is_symlink() or getattr(metadata, 'st_flags', 0) & 0x40000000 or metadata.st_size > 128 * 1024:
        raise ValueError('Regular bounded source required')
    return SQL.read_text()


def contract(text):
    functions = {match.group(1): match.group(2) for match in PATTERN.finditer(text)}
    if set(functions) != FUNCTIONS or len(list(PATTERN.finditer(text))) != len(FUNCTIONS):
        raise ValueError('Missing or duplicate integrity functions')
    for name in ('policy_binding_write_scope', 'policy_binding_event'):
        if 'PERFORM firefly_audit_private.require_record_hash(e);' not in functions['firefly_audit.' + name]:
            raise ValueError('Loaded canonical audit row must be recomputed')
    protocol = functions['insurance_policy_binding_private.verify_protocol']
    receipt = functions['insurance_policy_binding_private.verify_receipt']
    if "session_user<>'firefly_audit_writer'" not in protocol or 'insurance_policy_binding_private.protocol_state()' not in protocol:
        raise ValueError('Restricted protocol admission required')
    if 'PERFORM insurance_policy_binding_private.verify_protocol();' not in receipt or 'PERFORM insurance_policy_binding_private.binding_state(policy);' not in receipt:
        raise ValueError('Receipt acknowledgment must follow full verification')
    catalogue = functions['insurance_policy_binding_private.protocol_state']
    for predicate in ('NOT p.proisstrict', 'p.prorettype=expected.result_type', 'p.prosecdef=expected.definer',
                      'p.proconfig=ARRAY', 'IS NOT TRUE', 't.tgtype=expected.type_bits', 't.tginitdeferred=expected.deferred',
                      'c.confkey=ARRAY', "a.grantee=0", "a.is_grantable"):
        if predicate not in catalogue:
            raise ValueError('Complete null-safe metadata contract required')
    if 'insurance_policy_binding_private.protocol_state() IS NOT TRUE' not in protocol:
        raise ValueError('Null readiness must refuse')
    return functions


class PolicyV5SourceTest(unittest.TestCase):
    def test_original_v4_cannot_satisfy_new_integrity_contract(self):
        with self.assertRaisesRegex(ValueError, 'Missing or duplicate'):
            contract(V4.read_text())

    def test_candidate_has_both_real_repository_entrypoints_and_closed_helpers(self):
        self.assertEqual(len(contract(source())), 13)

    def test_removing_either_canonical_recompute_is_refused(self):
        text = source()
        self.assertEqual(text.count('PERFORM firefly_audit_private.require_record_hash(e);'), 2)
        for occurrence in (0, 1):
            pieces = text.split('PERFORM firefly_audit_private.require_record_hash(e);')
            mutated = pieces[0] + ('' if occurrence == 0 else 'PERFORM firefly_audit_private.require_record_hash(e);') + pieces[1]
            mutated += ('' if occurrence == 1 else 'PERFORM firefly_audit_private.require_record_hash(e);') + pieces[2]
            with self.subTest(occurrence=occurrence), self.assertRaisesRegex(ValueError, 'recomputed'):
                contract(mutated)

    def test_true_receipt_stub_and_incomplete_catalogue_are_refused(self):
        for old in ('PERFORM insurance_policy_binding_private.binding_state(policy);', 'NOT p.proisstrict', 'IS NOT TRUE'):
            with self.subTest(old=old), self.assertRaises(ValueError):
                contract(source().replace(old, 'REMOVED'))

    def test_predecessor_is_canonical_and_the_stream_has_exactly_two_phase_positions(self):
        body=contract(source())['firefly_audit.policy_binding_event']
        self.assertIn('PERFORM firefly_audit_private.require_record_hash(previous);',body)
        self.assertIn('e.sequence<>1',body)
        self.assertIn('e.sequence<>2 OR previous.sequence<>1',body)
        self.assertIn('e.previous_hash IS DISTINCT FROM previous.record_hash',body)

    def test_historical_proof_never_creates_or_reopens_an_audit_context(self):
        functions = contract(source())
        historical = functions['firefly_audit.policy_binding_event']
        for forbidden in ('firefly_audit_enter', 'context_for(', 'INSERT INTO', 'UPDATE ', 'until_time'):
            self.assertNotIn(forbidden, historical)
        current = functions['firefly_audit.policy_binding_write_scope']
        for required in ('pg_current_xact_id_if_assigned()', 'pg_backend_pid()', 'db_session_user=session_user', 'c.new_event',
                         'firefly_audit_private.completion', 'firefly_audit_private.context_for(c.nonce)'):
            self.assertIn(required, current)

    def test_two_policy_roles_and_phase_specific_revision_are_retained(self):
        receipt = contract(source())['insurance_policy_binding_private.receipt_state']
        self.assertIn('o.authorization_policy_revision,o.authorization_decision_id,o.admission_policy_revision,o.admission_decision_id', receipt)
        self.assertIn('o.owner_platform_tenant,o.admission_policy_revision,o.process_id', receipt)
        self.assertNotIn('o.authorization_policy_revision=o.admission_policy_revision', receipt)
        self.assertIn('CORE_POLICY_BIND_V1', receipt)
        self.assertIn('CORE_POLICY_ISSUE_V1', receipt)

    def test_null_readiness_cannot_acknowledge_a_protocol(self):
        with self.assertRaisesRegex(ValueError,'Null readiness'):
            contract(source().replace('insurance_policy_binding_private.protocol_state() IS NOT TRUE','NOT insurance_policy_binding_private.protocol_state()'))

    def test_original_bound_receipt_can_be_checked_after_activation(self):
        receipt = contract(source())['insurance_policy_binding_private.receipt_state']
        self.assertIn('(b.state=status AND b.binding_receipt_digest IS DISTINCT FROM receipt_digest)', receipt)
        self.assertIn("bound.operation='BIND' AND bound.event_id=b.bound_event_id", receipt)
        self.assertIn('keys:=array_append(keys,item.key)', receipt)
        self.assertIn('item.key=ANY(keys)', receipt)

    def test_every_phase_has_before_and_deferred_guards(self):
        text = source()
        before = re.findall(r'CREATE TRIGGER (\w+) BEFORE (.+?) ON ([\w.]+)', text)
        deferred = re.findall(r'CREATE CONSTRAINT TRIGGER (\w+) AFTER (.+?) ON ([\w.]+) DEFERRABLE INITIALLY DEFERRED', text)
        self.assertEqual(len(before), 9)
        self.assertEqual(len(deferred), 8)
        expected = {'public.policy', 'public.policy_party', 'public.policy_transaction', 'public.coverage', 'public.policy_status_history',
                    'insurance_policy_binding.binding', 'insurance_policy_binding.operation', 'insurance_policy_binding.receipt'}
        self.assertEqual({row[2] for row in deferred}, expected)
        self.assertTrue(expected <= {row[2] for row in before})

    def test_only_manual_narrow_runtime_activation_is_declared(self):
        text = source()
        self.assertNotRegex(text, r'(?i)\b(CREATE|ALTER)\s+ROLE|\bGRANT\s+\w+\s+TO\s+firefly_audit_writer')
        self.assertNotRegex(text, r'(?i)GRANT\s+SELECT\s+ON\s+firefly_audit\.')
        self.assertNotIn('DISABLE TRIGGER', text)
        self.assertNotIn('EXECUTE pg_catalog.format', text)
        self.assertIn('REVOKE REFERENCES(resource_tenant_id,event_id)', text)

    def test_all_existing_java_and_v1_through_v4_bytes_are_preserved(self):
        paths = subprocess.check_output(['git', '-C', str(ROOT), 'ls-tree', '-r', '--name-only', BASE], text=True).splitlines()
        protected = [path for path in paths if path.endswith('.java') or path.endswith('.sql')]
        for path in protected:
            expected = subprocess.check_output(['git', '-C', str(ROOT), 'show', BASE + ':' + path])
            observed=(ROOT / path).read_bytes()
            if path == 'core-insurance-policies-core/src/main/java/io/fireflysoftware/core/insurance/policies/core/services/binding/impl/SpringDataPolicyBindingStoreImpl.java':
                current=b'var mapper=strategy.getStatementMapper();'
                previous=b'var mapper=strategy.getStatementMapper().forType(row.getClass());'
                self.assertEqual(observed.count(current),1)
                observed=observed.replace(current,previous)
            if path == 'core-insurance-policies-models/src/main/java/io/fireflysoftware/core/insurance/policies/models/config/R2dbcConfiguration.java':
                for addition in (b'import io.fireflysoftware.core.insurance.policies.interfaces.enums.LineOfBusiness;\nimport io.fireflysoftware.core.insurance.policies.interfaces.enums.PolicyStatus;\nimport io.fireflysoftware.core.insurance.policies.models.config.impl.LineOfBusinessWriteConverterImpl;\nimport io.fireflysoftware.core.insurance.policies.models.config.impl.PolicyStatusWriteConverterImpl;\nimport io.r2dbc.postgresql.codec.EnumCodec;\nimport io.r2dbc.postgresql.extension.CodecRegistrar;\nimport java.util.List;\n',b'                        .codecRegistrar(policyEnumCodecs())\n',b'\n    public static CodecRegistrar policyEnumCodecs() {\n        return EnumCodec.builder()\n                .withEnum("policy_status_enum", PolicyStatus.class)\n                .withEnum("line_of_business_enum", LineOfBusiness.class)\n                .build();\n    }\n\n    public static List<Object> policyEnumConverters() {\n        return List.of(new PolicyStatusWriteConverterImpl(), new LineOfBusinessWriteConverterImpl());\n    }\n\n    @Override\n    protected List<Object> getCustomConverters() {\n        return policyEnumConverters();\n    }\n'):
                    self.assertEqual(observed.count(addition),1)
                    observed=observed.replace(addition,b'')
            if path == 'core-insurance-policies-core/src/main/java/io/fireflysoftware/core/insurance/policies/core/services/binding/PolicyBindingRuntimeConfiguration.java':
                current=b'new R2dbcEntityTemplate(client,new DefaultReactiveDataAccessStrategy(PostgresDialect.INSTANCE,R2dbcConfiguration.policyEnumConverters()))'
                previous=b'new R2dbcEntityTemplate(client,PostgresDialect.INSTANCE)'
                self.assertEqual(observed.count(current),1)
                observed=observed.replace(current,previous)
                for addition in (b'import io.fireflysoftware.core.insurance.policies.models.config.R2dbcConfiguration;\n',b'import org.springframework.data.r2dbc.core.DefaultReactiveDataAccessStrategy;\n'):
                    self.assertEqual(observed.count(addition),1)
                    observed=observed.replace(addition,b'')
            self.assertEqual(observed, expected, path)

    def test_digest_framing_keeps_opaque_scalar_bytes_and_boundaries(self):
        def digest(fields):
            output = bytearray()
            for field in fields:
                encoded = field.encode('utf8', 'strict')
                output += struct.pack('>I', len(encoded)) + encoded
            return hashlib.sha256(output).hexdigest()
        self.assertNotEqual(digest(['ab', 'c']), digest(['a', 'bc']))
        self.assertNotEqual(digest(['opaque subject']), digest(['opaque  subject']))
        self.assertNotEqual(digest(['é']), digest(['e\u0301']))
        self.assertNotEqual(digest(['auth-v1', 'id-A', 'admit-v1', 'id-B']), digest(['auth-v1', 'id-B', 'admit-v1', 'id-A']))
        with self.assertRaises(UnicodeEncodeError):
            digest(['bad\ud800'])
        body = contract(source())['insurance_policy_binding_private.hash_fields']
        self.assertIn("convert_to(field,'UTF8')", body)
        self.assertIn('int4send(octet_length(bytes))||bytes', body)


if __name__ == '__main__':
    unittest.main()
