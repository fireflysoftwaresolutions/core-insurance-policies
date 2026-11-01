package io.fireflysoftware.core.insurance.policies.web.governed;

import io.fireflysoftware.core.insurance.policies.core.services.binding.*;
import io.fireflysoftware.core.insurance.policies.core.services.binding.impl.SandboxPolicyBindingAdmissionImpl;
import io.fireflysoftware.core.insurance.policies.interfaces.binding.*;
import io.fireflysoftware.core.insurance.policies.web.controllers.GovernedPoliciesController;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.fireflyframework.security.adapter.opa.OpaPolicyEvaluationAdapter;
import org.fireflyframework.security.api.domain.SecurityPrincipal;
import org.fireflyframework.security.core.authority.*;
import org.fireflyframework.security.core.context.PrincipalFactory;
import org.fireflyframework.security.webflux.context.ReactorSecurityContextAdapter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.http.*;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.client.*;
import reactor.core.publisher.Mono;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class PolicyOwnerSecurityConfigurationTest {
    final Instant now=Instant.now();final UUID tenant=UUID.randomUUID(),party=UUID.randomUUID();final AtomicInteger pdpCalls=new AtomicInteger(),writes=new AtomicInteger();
    final String issuer="https://synthetic-issuer.invalid";final ReactiveJwtDecoder decoder=mock(ReactiveJwtDecoder.class);
    final PrincipalFactory principals=new PrincipalFactory(new ConfigurableAuthorityMapper(new AuthorityMappingProperties(List.of("roles"),List.of("scope"),"")));
    final GovernedPolicyBindRequest request=new GovernedPolicyBindRequest(UUID.randomUUID(),UUID.randomUUID(),party,UUID.randomUUID(),UUID.randomUUID(),1,1,UUID.randomUUID(),"a".repeat(64),"b".repeat(64),UUID.randomUUID(),"SANDBOX-1",LocalDate.of(2027,1,1),LocalDate.of(2028,1,1));
    Jwt token(String kind,String platform){
        return Jwt.withTokenValue("controlled-signed-token").header("alg","RS256").issuer(issuer).subject("opaque subject").claim("aud",List.of("policy")).claim("client_id","caller").claim("principal_kind",kind).claim("party_id",party.toString()).claim("tenant_id",platform).claim("scope","insurance:policies:bind insurance:policies:read insurance:policies:recover").notBefore(now.minusSeconds(1)).expiresAt(now.plusSeconds(60)).build();
    }
    WebTestClient client(){
        var pdp=new OpaPolicyEvaluationAdapter(WebClient.builder().baseUrl("https://synthetic-pdp.invalid").exchangeFunction(call->{
            int count=pdpCalls.incrementAndGet();return Mono.just(ClientResponse.create(HttpStatus.OK).header(HttpHeaders.CONTENT_TYPE,MediaType.APPLICATION_JSON_VALUE).body("{\"result\":{\"allow\":true,\"policy_revision\":\"policy-v1\"},\"decision_id\":\"actual-controlled-"+count+"\"}").build());
        }).build(),"policy/bind");
        var adapter=new ReactorSecurityContextAdapter();
        var authority=new SandboxPolicyBindingAdmissionImpl(adapter,pdp,new SandboxPolicyBindingAdmissionImpl.Profile(issuer,"policy","caller",tenant.toString(),tenant,UUID.randomUUID(),1,"c".repeat(64)),Clock.fixed(now,ZoneOffset.UTC),System::nanoTime,UUID::randomUUID);
        var delegate=new GovernedPolicyService(){
            public Mono<GovernedPolicyCommandResponse> bind(GovernedPolicyBindRequest value){
                return ReactiveSecurityContextHolder.getContext().flatMap(context->{
                    var held=assertInstanceOf(JwtAuthenticationToken.class,context.getAuthentication());assertEquals("controlled-signed-token",held.getToken().getTokenValue());
                    var principal=assertInstanceOf(SecurityPrincipal.class,held.getPrincipal());assertEquals("opaque subject",principal.subject());assertEquals(tenant.toString(),principal.tenantId());assertTrue(principal.scopes().contains("insurance:policies:bind"));
                    return authority.requireCurrent(PolicyBindingAdmission.Request.bind(value)).map(permit->{writes.incrementAndGet();return new GovernedPolicyCommandResponse(GovernedPolicyCommandResponse.Status.REFUSED,value.actionId(),value.intentDigest(),null);});
                });
            }
            public Mono<GovernedPolicyCommandResponse> issue(UUID id,GovernedPolicyIssueRequest value){return Mono.error(new AssertionError("unexpected issue"));}
            public Mono<GovernedPolicyRecoveryResponse> recover(UUID action,String digest){return Mono.error(new AssertionError("unexpected recovery"));}
        };
        var beans=new DefaultListableBeanFactory();beans.registerSingleton("governed",authority.scoped(delegate));var config=new PolicyOwnerSecurityConfiguration();
        return WebTestClient.bindToController(new GovernedPoliciesController(beans.getBeanProvider(GovernedPolicyService.class)))
                .webFilter(config.policyOwnerOnlyRoutes(),config.policyOwnerExceptionTranslation(),config.policyOwnerAuthentication(decoder,principals),config.policyOwnerAuthorization()).build();
    }
    @Test void nativeBoundaryRetainsVerifiedJwtAndRichOpaquePrincipalForCurrentPdp(){when(decoder.decode("controlled-signed-token")).thenReturn(Mono.just(token("HUMAN",tenant.toString())));
        client().post().uri("/api/v1/policies/governed/bindings").headers(h->h.setBearerAuth("controlled-signed-token")).bodyValue(request).exchange().expectStatus().isOk().expectBody().jsonPath("$.actionId").isEqualTo(request.actionId().toString());
        assertEquals(1,pdpCalls.get());assertEquals(1,writes.get());
    }
    @Test void missingBearerIs401BeforePdpOrBusiness(){client().post().uri("/api/v1/policies/governed/bindings").bodyValue(request).exchange().expectStatus().isUnauthorized();assertEquals(0,pdpCalls.get());assertEquals(0,writes.get());verifyNoInteractions(decoder);}
    @Test void nativeDecoderRefusalIs401BeforePdpOrBusiness(){when(decoder.decode("controlled-signed-token")).thenReturn(Mono.error(new BadJwtException("controlled refusal")));
        client().post().uri("/api/v1/policies/governed/bindings").headers(h->h.setBearerAuth("controlled-signed-token")).bodyValue(request).exchange().expectStatus().isUnauthorized();assertEquals(0,pdpCalls.get());assertEquals(0,writes.get());
    }
    @Test void staffCannotEnterTheHumanBusinessProfile(){when(decoder.decode("controlled-signed-token")).thenReturn(Mono.just(token("STAFF",tenant.toString())));
        client().post().uri("/api/v1/policies/governed/bindings").headers(h->h.setBearerAuth("controlled-signed-token")).bodyValue(request).exchange().expectStatus().isOk().expectBody().jsonPath("$.status").isEqualTo("REFUSED");assertEquals(0,pdpCalls.get());assertEquals(0,writes.get());
    }
    @Test void malformedSignedTenantIsNotNormalizedOrParsed(){when(decoder.decode("controlled-signed-token")).thenReturn(Mono.just(token("HUMAN","bad\ntenant")));
        client().post().uri("/api/v1/policies/governed/bindings").headers(h->h.setBearerAuth("controlled-signed-token")).bodyValue(request).exchange().expectStatus().isUnauthorized();assertEquals(0,pdpCalls.get());assertEquals(0,writes.get());
    }
    @Test void ownerModeClosesUnsupportedLegacyRoutesBeforeAuthentication(){client().get().uri("/api/v1/policies").exchange().expectStatus().isForbidden();assertEquals(0,pdpCalls.get());assertEquals(0,writes.get());verifyNoInteractions(decoder);}
    @Test void defaultOffLeavesExistingChainAndAddsNoOwnerAuthenticationBean(){
        var existing=mock(SecurityWebFilterChain.class);
        new ApplicationContextRunner().withBean(SecurityWebFilterChain.class,()->existing).withUserConfiguration(PolicyOwnerSecurityConfiguration.class).run(context->{
            assertNull(context.getStartupFailure());assertSame(existing,context.getBean(SecurityWebFilterChain.class));assertEquals(0,context.getBeanNamesForType(AuthenticationWebFilter.class).length);
        });
    }
}
