package io.fireflysoftware.core.insurance.policies.core.services.binding.fixture;

import io.fireflysoftware.core.insurance.policies.core.services.binding.*;
import io.fireflysoftware.core.insurance.policies.core.services.binding.impl.SpringDataPolicyBindingStoreImpl;
import io.fireflysoftware.core.insurance.policies.interfaces.binding.*;
import java.math.BigDecimal;
import java.time.*;
import java.util.*;
import org.fireflyframework.core.audit.AuditAppendAuthority;
import org.fireflyframework.core.transaction.CleanupPolicy;
import org.fireflyframework.kernel.audit.AuditActor;
import org.fireflyframework.security.api.domain.PolicyEvaluationProvenance;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/** Real SpringData mapping over controlled SPI; actual PostgreSQL acceptance remains the separate15-case gate. */
class AssignedPolicyInsertMappingTest {
    @Test void alreadyConvertedEnumColumnsRemainNativeDriverScalars(){
        var db=new PolicyBindingMappedFixture();String digest="a".repeat(64);UUID tenant=UUID.randomUUID();
        var request=new GovernedPolicyBindRequest(UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),1,1,UUID.randomUUID(),digest,digest,UUID.randomUUID(),"SANDBOX-1",LocalDate.of(2027,1,1),LocalDate.of(2028,1,1));
        var now=db.clock.instant();var permit=new PolicyBindingAdmission.Permit(PolicyBindingAdmission.Request.bind(request),tenant,request.partyId(),UUID.randomUUID(),1,digest,new AuditActor("https://synthetic.invalid","opaque subject","synthetic-client",tenant.toString(),null,null),"policy-v1",UUID.randomUUID(),UUID.randomUUID(),now,System.nanoTime(),now.plusSeconds(5));
        var authority=mock(PolicyBindingAdmission.class,withSettings().extraInterfaces(AuditAppendAuthority.class).defaultAnswer(CALLS_REAL_METHODS));
        when(authority.revalidate(any())).thenReturn(Mono.empty());when(authority.requireDecisionEvidence(any())).thenReturn(Mono.just(new PolicyBindingDecisionEvidence(new PolicyEvaluationProvenance("policy-v1","actual-authorization-control"),new PolicyEvaluationProvenance("policy-v1","actual-admission-control"))));
        when(((AuditAppendAuthority)authority).requireCurrent(any())).thenAnswer(call->{org.fireflyframework.kernel.audit.AuditEvent event=call.getArgument(0);return Mono.just(new AuditAppendAuthority.Permit(event.stream(),event.actor(),db.clock.instant().plusSeconds(1)));});
        var root=new PolicyBindingAuditRootImpl(db.resources,db.client,db.template,db.manager,new CleanupPolicy(Duration.ofSeconds(1),Duration.ofSeconds(1)),(AuditAppendAuthority)authority,authority,db.clock,db.nanos);
        var store=new SpringDataPolicyBindingStoreImpl(db.template,root,UUID::randomUUID);
        var quote=new AcceptedQuoteEvidence(tenant,request.submissionId(),request.partyId(),request.productId(),request.offerId(),1,1,request.acceptanceActionId(),UUID.randomUUID(),digest,digest,"USD",new BigDecimal("25.00"),new BigDecimal("1.25"),new BigDecimal("10.00"),Map.of("coverageCode","SANDBOX_PROPERTY_DAMAGE","coverageStart","2027-01-01","coverageEnd","2028-01-01","insuredLimit","1000.00","deductible","100.00","wording","Illustrative only","exclusions","Synthetic exclusions"),UUID.randomUUID(),digest,digest,"firefly-sandbox-property-1","illustrative-property-1",db.clock.instant().truncatedTo(java.time.temporal.ChronoUnit.MICROS),"https://synthetic.invalid","opaque subject");
        var result=store.bind(permit,request,quote).block(Duration.ofSeconds(2));assertNotNull(result);assertEquals(GovernedPolicyCommandResponse.Status.COMMITTED,result.status());
        assertEquals("POLICYHOLDER",db.driver.tables.get("policy_party").getFirst().get("role"));
        assertEquals("PROPERTY",db.driver.tables.get("policy").getFirst().get("line_of_business"));
        assertEquals("BOUND",db.driver.tables.get("policy").getFirst().get("policy_status"));
        assertEquals("NEW_BUSINESS",db.driver.tables.get("policy_transaction").getFirst().get("transaction_type"));
        assertTrue(db.driver.bindings.stream().flatMap(values->values.values().stream()).noneMatch(Enum.class::isInstance));
    }
}
