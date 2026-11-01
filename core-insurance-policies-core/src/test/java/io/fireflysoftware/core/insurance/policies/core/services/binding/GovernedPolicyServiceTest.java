package io.fireflysoftware.core.insurance.policies.core.services.binding;

import io.fireflysoftware.core.insurance.policies.core.services.binding.impl.GovernedPolicyServiceImpl;
import io.fireflysoftware.core.insurance.policies.interfaces.binding.*;
import java.math.BigDecimal;
import java.time.*;
import java.util.Map;
import java.util.UUID;
import org.fireflyframework.kernel.audit.AuditActor;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class GovernedPolicyServiceTest {
    final Instant now=Instant.parse("2026-10-31T12:00:00Z");final Clock clock=Clock.fixed(now,ZoneOffset.UTC);
    final PolicyBindingAdmission authority=mock(PolicyBindingAdmission.class);final AcceptedQuotePort quotes=mock(AcceptedQuotePort.class);
    final PolicyContractPort contracts=mock(PolicyContractPort.class);final PolicyBindingStore store=mock(PolicyBindingStore.class);
    final GovernedPolicyService service=new GovernedPolicyServiceImpl(authority,quotes,contracts,store,clock);
    final String digest="a".repeat(64);final UUID tenant=UUID.randomUUID();
    final GovernedPolicyBindRequest request=new GovernedPolicyBindRequest(UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),1,1,UUID.randomUUID(),digest,digest,UUID.randomUUID(),"SANDBOX-1",LocalDate.of(2027,1,1),LocalDate.of(2028,1,1));
    final PolicyBindingAdmission.Request command=PolicyBindingAdmission.Request.bind(request);
    final PolicyBindingAdmission.Permit permit=new PolicyBindingAdmission.Permit(command,tenant,request.partyId(),UUID.randomUUID(),1,digest,new AuditActor("https://synthetic.invalid","opaque subject","staff-client","opaque-platform",null,null),"policy-v1",UUID.randomUUID(),UUID.randomUUID(),now,System.nanoTime(),now.plusSeconds(5));
    AcceptedQuoteEvidence quote(UUID scopeTenant){return new AcceptedQuoteEvidence(scopeTenant,request.submissionId(),request.partyId(),request.productId(),request.offerId(),1,1,request.acceptanceActionId(),UUID.randomUUID(),digest,digest,"USD",new BigDecimal("25.00"),new BigDecimal("1.25"),new BigDecimal("10.00"),Map.of("coverageCode","SANDBOX_PROPERTY_DAMAGE","coverageStart","2027-01-01","coverageEnd","2028-01-01"),UUID.randomUUID(),digest,digest,"firefly-sandbox-property-1","illustrative-property-1",now,"https://synthetic.invalid","opaque subject");}
    void admit(){when(authority.requireCurrent(command)).thenReturn(Mono.just(permit));when(authority.revalidate(permit)).thenReturn(Mono.empty());when(quotes.observe(permit,request)).thenReturn(Mono.just(quote(tenant)));when(contracts.requireExisting(eq(permit),eq(request),any())).thenReturn(Mono.empty());}
    @Test void missingCurrentAuthorityCannotReadQuotesOrWriteBusiness(){when(authority.requireCurrent(command)).thenReturn(Mono.empty());StepVerifier.create(service.bind(request)).expectError(GovernedPolicyUnavailableException.class).verify();verifyNoInteractions(quotes,contracts,store);}
    @Test void anotherTenantAcceptedQuoteCannotEnterTheWriteRoot(){admit();when(quotes.observe(permit,request)).thenReturn(Mono.just(quote(UUID.randomUUID())));StepVerifier.create(service.bind(request)).assertNext(r->assertEquals(GovernedPolicyCommandResponse.Status.REFUSED,r.status())).verifyComplete();verifyNoInteractions(contracts,store);}
    @Test void absentOwnerObservationCannotBecomeBound(){admit();when(quotes.observe(permit,request)).thenReturn(Mono.empty());StepVerifier.create(service.bind(request)).assertNext(r->assertEquals(GovernedPolicyCommandResponse.Status.REFUSED,r.status())).verifyComplete();verifyNoInteractions(contracts,store);}
    @Test void contractReadFailureCannotBecomeACommittedOrRetriedOperation(){admit();when(contracts.requireExisting(eq(permit),eq(request),any())).thenReturn(Mono.error(new IllegalStateException("synthetic")));StepVerifier.create(service.bind(request)).assertNext(value->{assertEquals(GovernedPolicyCommandResponse.Status.REFUSED,value.status());assertEquals(request.actionId(),value.actionId());}).verifyComplete();verifyNoInteractions(store);}
    @Test void anUncertainRootKeepsTheExactOriginalActionAndNeverBecomes503(){admit();when(store.bind(eq(permit),eq(request),any())).thenReturn(Mono.error(new IllegalStateException("private database detail")));StepVerifier.create(service.bind(request)).assertNext(result->{assertEquals(GovernedPolicyCommandResponse.Status.OUTCOME_UNKNOWN,result.status());assertEquals(request.actionId(),result.actionId());assertEquals(request.intentDigest(),result.intentDigest());assertNull(result.result());}).verifyComplete();verify(store).bind(eq(permit),eq(request),any());}
    @Test void knownRootRefusalIsPreservedWithoutManufacturedSuccess(){admit();var refused=new GovernedPolicyCommandResponse(GovernedPolicyCommandResponse.Status.REFUSED,request.actionId(),request.intentDigest(),null);when(store.bind(eq(permit),eq(request),any())).thenReturn(Mono.just(refused));StepVerifier.create(service.bind(request)).expectNext(refused).verifyComplete();}
    @Test void requestCollectionsAreDefensiveAndDiagnosticsDoNotExposeTerms(){var snapshot=quote(tenant);assertThrows(UnsupportedOperationException.class,()->snapshot.coverageTerms().put("secret","value"));assertEquals("AcceptedQuoteEvidence[redacted]",snapshot.toString());assertFalse(request.toString().contains("SANDBOX-1"));}
}
