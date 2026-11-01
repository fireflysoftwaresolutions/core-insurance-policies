package io.fireflysoftware.core.insurance.policies.web.controllers;

import io.fireflysoftware.core.insurance.policies.core.services.binding.*;
import io.fireflysoftware.core.insurance.policies.interfaces.binding.*;
import java.time.LocalDate;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class GovernedPoliciesControllerTest {
    final UUID action=UUID.randomUUID();final String digest="a".repeat(64);
    GovernedPolicyBindRequest request(){return new GovernedPolicyBindRequest(action,UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),1,1,UUID.randomUUID(),digest,digest,UUID.randomUUID(),"SANDBOX-1",LocalDate.of(2027,1,1),LocalDate.of(2028,1,1));}
    WebTestClient client(DefaultListableBeanFactory beans){return WebTestClient.bindToController(new GovernedPoliciesController(beans.getBeanProvider(GovernedPolicyService.class))).build();}
    @Test void missingTrustedServiceRefusesBeforeAnyBusinessCall(){client(new DefaultListableBeanFactory()).post().uri("/api/v1/policies/governed/bindings").bodyValue(request()).exchange().expectStatus().isEqualTo(503);}
    @Test void uncertainRootIs200WithOriginalIdentityAndNoMadeUpPolicy(){var service=mock(GovernedPolicyService.class);var body=request();when(service.bind(any())).thenReturn(Mono.just(new GovernedPolicyCommandResponse(GovernedPolicyCommandResponse.Status.OUTCOME_UNKNOWN,body.actionId(),body.intentDigest(),null)));var beans=new DefaultListableBeanFactory();beans.registerSingleton("governed",service);
        client(beans).post().uri("/api/v1/policies/governed/bindings").bodyValue(body).exchange().expectStatus().isOk().expectBody().jsonPath("$.status").isEqualTo("OUTCOME_UNKNOWN").jsonPath("$.actionId").isEqualTo(action.toString()).jsonPath("$.intentDigest").isEqualTo(body.intentDigest()).jsonPath("$.result").doesNotExist();verify(service).bind(body);}
    @Test void recoveryNeverStartsAnotherBinding(){var service=mock(GovernedPolicyService.class);when(service.recover(action,digest)).thenReturn(Mono.just(new GovernedPolicyRecoveryResponse(GovernedPolicyRecoveryResponse.State.NOT_OBSERVED_AT_THIS_READ,action,digest,null)));var beans=new DefaultListableBeanFactory();beans.registerSingleton("governed",service);
        client(beans).get().uri("/api/v1/policies/governed/recovery/"+action+"?intentDigest="+digest).exchange().expectStatus().isOk().expectBody().jsonPath("$.state").isEqualTo("NOT_OBSERVED_AT_THIS_READ");verify(service).recover(action,digest);verifyNoMoreInteractions(service);}
}
