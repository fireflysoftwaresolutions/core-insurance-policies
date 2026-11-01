package io.fireflysoftware.core.insurance.policies.core.services.binding.impl;

import io.fireflysoftware.core.insurance.policies.core.services.binding.*;
import io.fireflysoftware.core.insurance.policies.interfaces.binding.*;
import io.fireflysoftware.core.insurance.policies.interfaces.enums.PolicyStatus;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import org.fireflyframework.security.api.domain.SecurityPrincipal;
import org.fireflyframework.security.adapter.opa.OpaPolicyEvaluationAdapter;
import org.junit.jupiter.api.Test;
import org.springframework.http.*;
import org.springframework.web.reactive.function.client.*;
import reactor.core.publisher.Mono;
import static org.junit.jupiter.api.Assertions.*;

/** Actual managed OPA adapter over a controlled ExchangeFunction; no external engine/provider authority claim. */
class SandboxPolicyBindingAdmissionTest {
    final UUID tenant=UUID.randomUUID(),party=UUID.randomUUID();final String issuer="https://synthetic.invalid",digest="a".repeat(64);
    final AtomicInteger calls=new AtomicInteger(),work=new AtomicInteger();final AtomicReference<String> kind=new AtomicReference<>("HUMAN");
    final MovingClock clock=new MovingClock();String response="{\"result\":{\"allow\":true,\"policy_revision\":\"actual-policy-7\"},\"decision_id\":\"actual-decision-%d\"}";
    final GovernedPolicyBindRequest request=new GovernedPolicyBindRequest(UUID.randomUUID(),UUID.randomUUID(),party,UUID.randomUUID(),UUID.randomUUID(),1,1,UUID.randomUUID(),digest,digest,UUID.randomUUID(),"SANDBOX-1",LocalDate.of(2027,1,1),LocalDate.of(2028,1,1));
    SecurityPrincipal principal(String platform){return SecurityPrincipal.builder().issuer(issuer).subject("opaque subject").tenantId(platform).scopes(Set.of("insurance:policies:bind","insurance:policies:read","insurance:policies:recover")).claims(Map.of("principal_kind",kind.get(),"party_id",party.toString(),"client_id","owned-client","aud",List.of("policy-audience"),"exp",clock.initial.plusSeconds(60),"nbf",clock.initial.minusSeconds(1))).build();}
    SandboxPolicyBindingAdmissionImpl runtime(String platform){var engine=new OpaPolicyEvaluationAdapter(WebClient.builder().baseUrl("https://synthetic-policy.invalid").exchangeFunction(call->{int count=calls.incrementAndGet();return Mono.just(ClientResponse.create(HttpStatus.OK).header(HttpHeaders.CONTENT_TYPE,"application/json").body(response.formatted(count)).build());}).build(),"core/policy/bind");return new SandboxPolicyBindingAdmissionImpl(()->Mono.just(principal(platform)),engine,new SandboxPolicyBindingAdmissionImpl.Profile(issuer,"policy-audience","owned-client",tenant.toString(),tenant,UUID.randomUUID(),1,digest),clock,System::nanoTime,UUID::randomUUID);}
    GovernedPolicyCommandResponse marker(){return new GovernedPolicyCommandResponse(GovernedPolicyCommandResponse.Status.REFUSED,request.actionId(),request.intentDigest(),null);}
    GovernedPolicyService delegate(java.util.function.Function<GovernedPolicyBindRequest,Mono<GovernedPolicyCommandResponse>> binding){return new GovernedPolicyService(){public Mono<GovernedPolicyCommandResponse> bind(GovernedPolicyBindRequest r){work.incrementAndGet();return binding.apply(r);}public Mono<GovernedPolicyCommandResponse> issue(UUID id,GovernedPolicyIssueRequest r){return Mono.error(new AssertionError("unexpected issue"));}public Mono<GovernedPolicyRecoveryResponse> recover(UUID id,String hash){return Mono.error(new AssertionError("unexpected recovery"));}};}
    @Test void actualOpaSameResponseIdsAreCapturedForBothRoles(){var runtime=runtime(tenant.toString());var service=runtime.scoped(delegate(r->runtime.requireCurrent(PolicyBindingAdmission.Request.bind(r)).flatMap(permit->runtime.revalidate(permit).then(runtime.requireDecisionEvidence(permit))).map(evidence->{assertEquals("actual-decision-1",evidence.authorization().decisionId());assertEquals("actual-decision-2",evidence.admission().decisionId());return marker();})));assertEquals(marker(),service.bind(request).block(Duration.ofSeconds(2)));assertEquals(2,calls.get());}
    @Test void valueOnlyRequestCannotActivatePrivateAuthority(){var runtime=runtime(tenant.toString());assertThrows(PolicyBindingRefusedException.class,()->runtime.requireCurrent(PolicyBindingAdmission.Request.bind(request)).block());assertEquals(0,calls.get());}
    @Test void staffCannotBorrowTheHumanSandboxProfile(){kind.set("STAFF");var runtime=runtime(tenant.toString());assertEquals(GovernedPolicyCommandResponse.Status.REFUSED,runtime.scoped(delegate(r->Mono.just(marker()))).bind(request).block().status());assertEquals(0,work.get());assertEquals(0,calls.get());}
    @Test void opaquePlatformNamespaceIsNotParsedAsResourceTenant(){var runtime=runtime("opaque-platform");assertEquals(GovernedPolicyCommandResponse.Status.REFUSED,runtime.scoped(delegate(r->Mono.just(marker()))).bind(request).block().status());assertEquals(0,work.get());assertEquals(0,calls.get());}
    @Test void aGrantedResponseWithoutOriginalDecisionIdRefuses(){response="{\"result\":{\"allow\":true,\"policy_revision\":\"actual-policy-7\"}}";var runtime=runtime(tenant.toString());var result=runtime.scoped(delegate(r->runtime.requireCurrent(PolicyBindingAdmission.Request.bind(r)).thenReturn(marker()))).bind(request).block();assertEquals(GovernedPolicyCommandResponse.Status.REFUSED,result.status());assertEquals(1,calls.get());}
    @Test void originalIntentIsBoundToPdpFactsWithoutPlainPolicyNumber(){var runtime=runtime(tenant.toString());var service=runtime.scoped(delegate(r->runtime.requireCurrent(PolicyBindingAdmission.Request.bind(r)).map(permit->{assertEquals(r,permit.request().bindingIntent());assertEquals(r.partyId(),permit.partyId());return marker();})));assertNotNull(service.bind(request).block());assertEquals(1,calls.get());}
    @Test void lateProjectionAfterEagerCleanupCannotEmitACommittedResult(){var runtime=runtime(tenant.toString());var receipt=new GovernedPolicyBindingResult(UUID.randomUUID(),request.policyNumber(),PolicyStatus.BOUND,1,digest,request.acceptanceActionId(),UUID.randomUUID(),request.offerId(),1,request.termsDigest());var committed=new GovernedPolicyCommandResponse(GovernedPolicyCommandResponse.Status.COMMITTED,request.actionId(),request.intentDigest(),receipt);
        var value=runtime.scoped(delegate(r->Mono.just(committed).doOnSuccess(ignored->clock.now.set(clock.initial.plusSeconds(6))))).bind(request).block();assertEquals(GovernedPolicyCommandResponse.Status.COMMITTED_RESPONSE_UNAVAILABLE,value.status());assertEquals(request.actionId(),value.actionId());assertNull(value.result());}
    static final class MovingClock extends Clock {final Instant initial=Instant.parse("2026-10-31T12:00:00Z");final AtomicReference<Instant> now=new AtomicReference<>(initial);public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId zone){return this;}public Instant instant(){return now.get();}}
}
