package io.fireflysoftware.core.insurance.policies.core.services.binding.impl;

import io.fireflysoftware.core.insurance.policies.core.services.binding.*;
import io.fireflysoftware.core.insurance.policies.interfaces.binding.*;
import io.fireflysoftware.core.insurance.policies.interfaces.enums.PolicyStatus;
import java.time.*;
import java.util.UUID;
import org.fireflyframework.security.adapter.opa.OpaPolicyEvaluationAdapter;
import org.junit.jupiter.api.Test;
import org.springframework.http.*;
import org.springframework.web.reactive.function.client.*;
import reactor.core.publisher.Mono;
import static org.junit.jupiter.api.Assertions.*;

class PolicyConfigurationExpiryTest {
    final SandboxPolicyBindingAdmissionTest fixture=new SandboxPolicyBindingAdmissionTest();
    SandboxPolicyBindingAdmissionImpl runtime(Instant until){
        var pdp=new OpaPolicyEvaluationAdapter(WebClient.builder().baseUrl("https://synthetic-pdp.invalid").exchangeFunction(request->{
            int count=fixture.calls.incrementAndGet();return Mono.just(ClientResponse.create(HttpStatus.OK).header(HttpHeaders.CONTENT_TYPE,"application/json").body(fixture.response.formatted(count)).build());
        }).build(),"policy/bind");
        return new SandboxPolicyBindingAdmissionImpl(()->Mono.just(fixture.principal(fixture.tenant.toString())),pdp,
                new SandboxPolicyBindingAdmissionImpl.Profile(fixture.issuer,"policy-audience","owned-client",fixture.tenant.toString(),fixture.tenant,UUID.randomUUID(),1,fixture.digest),
                fixture.clock,System::nanoTime,UUID::randomUUID,until);
    }
    @Test void finiteServerBindingNarrowsTheOriginalAuthorityWindow(){
        var until=fixture.clock.initial.plusSeconds(1);var runtime=runtime(until);
        var service=runtime.scoped(fixture.delegate(request->runtime.requireCurrent(PolicyBindingAdmission.Request.bind(request)).map(permit->{
            assertEquals(until,permit.notAfter());return fixture.marker();
        })));
        assertNotNull(service.bind(fixture.request).block(Duration.ofSeconds(2)));assertEquals(1,fixture.calls.get());
    }
    @Test void expiredServerBindingRefusesBeforePdpAndBusinessWork(){
        var runtime=runtime(fixture.clock.initial);
        assertEquals(GovernedPolicyCommandResponse.Status.REFUSED,runtime.scoped(fixture.delegate(request->Mono.just(fixture.marker()))).bind(fixture.request).block().status());
        assertEquals(0,fixture.calls.get());assertEquals(0,fixture.work.get());
    }
    @Test void configurationExpiryAfterCommittedProjectionRetainsTheOriginalAction(){
        var runtime=runtime(fixture.clock.initial.plusSeconds(1));var request=fixture.request;
        var receipt=new GovernedPolicyBindingResult(UUID.randomUUID(),request.policyNumber(),PolicyStatus.BOUND,1,fixture.digest,request.acceptanceActionId(),UUID.randomUUID(),request.offerId(),1,request.termsDigest());
        var response=new GovernedPolicyCommandResponse(GovernedPolicyCommandResponse.Status.COMMITTED,request.actionId(),request.intentDigest(),receipt);
        var observed=runtime.scoped(fixture.delegate(value->Mono.just(response).doOnSuccess(ignored->fixture.clock.now.set(fixture.clock.initial.plusSeconds(2))))).bind(request).block();
        assertEquals(GovernedPolicyCommandResponse.Status.COMMITTED_RESPONSE_UNAVAILABLE,observed.status());assertEquals(request.actionId(),observed.actionId());assertEquals(request.intentDigest(),observed.intentDigest());assertNull(observed.result());
    }
}
