package io.fireflysoftware.core.insurance.policies.sdk;

import io.fireflysoftware.core.insurance.policies.sdk.api.GovernedPoliciesApi;
import io.fireflysoftware.core.insurance.policies.sdk.invoker.ApiClient;
import io.fireflysoftware.core.insurance.policies.sdk.model.*;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.http.*;
import org.springframework.http.client.reactive.*;
import org.springframework.mock.http.client.reactive.*;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;
import reactor.test.StepVerifier;
import static org.junit.jupiter.api.Assertions.*;

/** Controlled generated transport only; no database, provider, signed caller or issuance acceptance. */
class GovernedPolicyGeneratedSdkTest {
    static final String DIGEST="a".repeat(64);
    record Captured(String path,List<String> authorization,String body,String retryKey){}
    static final class TransportFixtureImpl {
        final UUID action=UUID.randomUUID(),policy=UUID.randomUUID();
        final List<Captured> captured=new CopyOnWriteArrayList<>();
        final AtomicReference<String> status=new AtomicReference<>("OUTCOME_UNKNOWN");
        final AtomicReference<HttpStatus> http=new AtomicReference<>(HttpStatus.OK);
        Mono<Void> gate=Mono.empty();
        final GovernedPoliciesApi api;
        TransportFixtureImpl(String token){
            ClientHttpConnector connector=(method,uri,callback)->{
                var request=new MockClientHttpRequest(method,uri);
                return callback.apply(request).then(Mono.defer(request::getBodyAsString)).flatMap(body->{
                    captured.add(new Captured(uri.getPath(),List.copyOf(request.getHeaders().getOrEmpty(HttpHeaders.AUTHORIZATION)),body,request.getHeaders().getFirst("X-Idempotency-Key")));
                    var response=new MockClientHttpResponse(http.get());response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
                    String payload=uri.getPath().contains("/recovery/")?
                            "{\"state\":\"NOT_OBSERVED_AT_THIS_READ\",\"actionId\":\""+action+"\",\"intentDigest\":\""+DIGEST+"\"}":
                            "{\"status\":\""+status.get()+"\",\"actionId\":\""+action+"\",\"intentDigest\":\""+DIGEST+"\""+(status.get().equals("COMMITTED")?",\"result\":{\"policyId\":\""+policy+"\",\"policyNumber\":\"SANDBOX-1\",\"policyStatus\":\"BOUND\",\"bindingVersion\":1,\"bindingReceiptDigest\":\""+DIGEST+"\",\"acceptanceActionId\":\""+action+"\",\"acceptanceId\":\""+UUID.randomUUID()+"\",\"offerId\":\""+UUID.randomUUID()+"\",\"offerVersion\":1,\"termsDigest\":\""+DIGEST+"\"}":"")+"}";
                    response.setBody(payload);return gate.thenReturn((ClientHttpResponse)response);
                });
            };
            var client=new ApiClient(ApiClient.buildWebClientBuilder().clientConnector(connector).build()).setBasePath("https://synthetic-policy.invalid");
            client.setBearerToken(token);api=new GovernedPoliciesApi(client);
        }
        GovernedPolicyBindRequest bindRequest()throws Exception{
            String json="{\"actionId\":\""+action+"\",\"submissionId\":\""+UUID.randomUUID()+"\",\"partyId\":\""+UUID.randomUUID()+"\",\"productId\":\""+UUID.randomUUID()+"\",\"offerId\":\""+UUID.randomUUID()+"\",\"offerVersion\":1,\"acceptedControlGeneration\":1,\"acceptanceActionId\":\""+UUID.randomUUID()+"\",\"acceptanceIntentDigest\":\""+DIGEST+"\",\"termsDigest\":\""+DIGEST+"\",\"contractId\":\""+UUID.randomUUID()+"\",\"policyNumber\":\"SANDBOX-1\",\"inceptionDate\":\"2027-01-01\",\"expiryDate\":\"2028-01-01\"}";
            return ApiClient.createDefaultMapper(null).readValue(json,GovernedPolicyBindRequest.class);
        }
        GovernedPolicyIssueRequest issueRequest()throws Exception{
            return ApiClient.createDefaultMapper(null).readValue("{\"actionId\":\""+action+"\",\"expectedBindingVersion\":1,\"bindingReceiptDigest\":\""+DIGEST+"\"}",GovernedPolicyIssueRequest.class);
        }
    }
    @Test void originalGeneratorDecodesAllFourOutcomesAndPreservesStableActionAndRefusal()throws Exception{
        var fixture=new TransportFixtureImpl("controlled-human-A");
        for(Class<?> type:List.of(GovernedPoliciesApi.class,GovernedPolicyCommandResponse.class,GovernedPolicyRecoveryResponse.class))
            assertEquals(Path.of("target/classes").toRealPath(),Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath());
        for(String status:List.of("COMMITTED","COMMITTED_RESPONSE_UNAVAILABLE","OUTCOME_UNKNOWN","REFUSED")){
            fixture.status.set(status);
            GovernedPolicyCommandResponse value=fixture.api.bindGovernedPolicyWithHttpInfo(fixture.bindRequest()).block(Duration.ofSeconds(2)).getBody();
            assertNotNull(value);assertEquals(status,value.getStatus().toString());assertEquals(fixture.action,value.getActionId());assertEquals(DIGEST,value.getIntentDigest());
            if(status.equals("COMMITTED"))assertEquals(fixture.policy,value.getResult().getPolicyId());else assertNull(value.getResult());
        }
        assertEquals(4,fixture.captured.size());
        for(var sent:fixture.captured){
            assertEquals(List.of("Bearer controlled-human-A"),sent.authorization());assertNull(sent.retryKey());
            assertEquals(fixture.action.toString(),ApiClient.createDefaultMapper(null).readTree(sent.body()).path("actionId").asText());
        }
        fixture.http.set(HttpStatus.FORBIDDEN);
        assertThrows(WebClientResponseException.Forbidden.class,()->fixture.api.bindGovernedPolicyWithHttpInfo(fixture.bindRequest()).block(Duration.ofSeconds(2)));
    }
    @Test void callerBoundRecoveryAndActivationNeverShareMutableBearerCredentials()throws Exception{
        var left=new TransportFixtureImpl("controlled-human-A");var right=new TransportFixtureImpl("controlled-human-B");
        var gate=Sinks.<Void>empty();left.gate=gate.asMono();right.gate=gate.asMono();var issue=right.issueRequest();
        StepVerifier.create(Mono.zip(left.api.recoverGovernedPolicyBindingWithHttpInfo(left.action,DIGEST,null),right.api.issueGovernedPolicyWithHttpInfo(right.policy,issue)))
                .expectSubscription().then(()->{assertEquals(1,left.captured.size());assertEquals(1,right.captured.size());gate.tryEmitEmpty();})
                .assertNext(pair->{
                    GovernedPolicyRecoveryResponse recovery=pair.getT1().getBody();GovernedPolicyCommandResponse activation=pair.getT2().getBody();
                    assertNotNull(recovery);assertEquals(left.action,recovery.getActionId());assertEquals(DIGEST,recovery.getIntentDigest());
                    assertEquals("NOT_OBSERVED_AT_THIS_READ",recovery.getState().toString());assertNotNull(activation);assertEquals(right.action,activation.getActionId());assertEquals("OUTCOME_UNKNOWN",activation.getStatus().toString());
                    assertNotSame(left.api.getApiClient(),right.api.getApiClient());assertEquals(List.of("Bearer controlled-human-A"),left.captured.getFirst().authorization());assertEquals(List.of("Bearer controlled-human-B"),right.captured.getFirst().authorization());
                    assertNull(left.captured.getFirst().retryKey());assertNull(right.captured.getFirst().retryKey());
                }).verifyComplete();
    }
}
