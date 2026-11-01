package io.fireflysoftware.core.insurance.policies.core.services.binding.impl;

import io.fireflysoftware.core.insurance.policies.core.services.binding.*;
import java.net.URI;
import java.time.*;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.*;
import org.fireflyframework.kernel.audit.AuditActor;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ClientHttpResponse;
import org.springframework.mock.http.client.reactive.MockClientHttpRequest;
import org.springframework.mock.http.client.reactive.MockClientHttpResponse;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Mono;
import org.springframework.web.server.ResponseStatusException;
import reactor.test.StepVerifier;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Native transport/decoder SPI controls; the constructed Jwt values do not establish signature or provider acceptance. */
class ExchangedPolicyContractClientProviderTest {
    final Instant now=Instant.parse("2026-10-31T12:00:00Z");final Clock clock=Clock.fixed(now,ZoneOffset.UTC);
    final UUID tenant=UUID.randomUUID(),party=UUID.randomUUID(),action=UUID.randomUUID();final String issuer="https://synthetic-issuer.invalid";final String platformTenant="synthetic:opaque:policy-tenant";
    final AtomicInteger calls=new AtomicInteger();final AtomicReference<String> form=new AtomicReference<>();final ReactiveJwtDecoder decoder=mock(ReactiveJwtDecoder.class);
    final io.fireflysoftware.core.insurance.policies.interfaces.binding.GovernedPolicyBindRequest bindingRequest=new io.fireflysoftware.core.insurance.policies.interfaces.binding.GovernedPolicyBindRequest(action,UUID.randomUUID(),party,UUID.randomUUID(),UUID.randomUUID(),1,1,UUID.randomUUID(),"a".repeat(64),"a".repeat(64),UUID.randomUUID(),"SANDBOX-1",java.time.LocalDate.of(2027,1,1),java.time.LocalDate.of(2028,1,1));
    final PolicyBindingAdmission.Permit permit=new PolicyBindingAdmission.Permit(PolicyBindingAdmission.Request.bind(bindingRequest),tenant,party,UUID.randomUUID(),1,"b".repeat(64),new AuditActor(issuer,"opaque subject","inbound-client",platformTenant,null,null),"policy-v1",UUID.randomUUID(),UUID.randomUUID(),now,System.nanoTime(),now.plusSeconds(5));
    final PolicyContractClientProvider.ServerBinding serverBinding=new PolicyContractClientProvider.ServerBinding(tenant,permit.bindingId(),permit.bindingVersion(),permit.bindingDigest(),URI.create("https://contracts.invalid"),UUID.randomUUID(),now.plusSeconds(60));
    final AtomicReference<String> tokenReply=new AtomicReference<>("{\"access_token\":\"synthetic-exchanged-token\",\"token_type\":\"Bearer\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\",\"expires_in\":30,\"scope\":\"contracts:read contracts:parties:read\"}");
    final AtomicReference<Mono<Void>> responseGate=new AtomicReference<>(Mono.empty());
    Jwt jwt(String value,String kind,String subject,String audience,String client,Instant expiry){return Jwt.withTokenValue(value).header("alg","RS256").issuer(issuer).subject(subject).claim("aud",List.of(audience)).claim("client_id",client).claim("principal_kind",kind).claim("tenant_id",platformTenant).claim("party_id",party.toString()).claim("scope","policy-audience".equals(audience)?"insurance:policies:bind":"contracts:read contracts:parties:read").issuedAt(now.minusSeconds(1)).notBefore(now.minusSeconds(1)).expiresAt(expiry).build();}
    Jwt inbound(){return jwt("synthetic-subject-token","HUMAN","opaque subject","policy-audience","inbound-client",now.plusSeconds(60));}
    Jwt target(){return jwt("synthetic-exchanged-token","HUMAN","opaque subject","contract-audience","policy-contract-exchange",now.plusSeconds(30));}
    ClientRegistration registration(AuthorizationGrantType grant){return ClientRegistration.withRegistrationId("owned-exchange").clientId("policy-contract-exchange").clientSecret("synthetic-secret").clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).authorizationGrantType(grant).tokenUri(issuer+"/token").scope("contracts:read","contracts:parties:read").build();}
    ClientHttpConnector connector(){return (method,uri,callback)->{calls.incrementAndGet();var request=new MockClientHttpRequest(method,uri);return callback.apply(request).then(Mono.defer(request::getBodyAsString).flatMap(body->{form.set(body);var response=new MockClientHttpResponse(HttpStatus.OK);response.getHeaders().setContentType(MediaType.APPLICATION_JSON);response.setBody(body.contains("subject_token=synthetic-subject-b")?tokenReply.get().replace("synthetic-exchanged-token","synthetic-exchanged-b"):tokenReply.get());return responseGate.get().then(Mono.<ClientHttpResponse>just(response));}));};}
    ExchangedPolicyContractClientProviderImpl factory(){return new ExchangedPolicyContractClientProviderImpl(registration(AuthorizationGrantType.TOKEN_EXCHANGE),issuer,"contract-audience","client_id","policy-contract-exchange",serverBinding,decoder,clock,connector());}
    <T> Mono<T> context(Mono<T> result,Jwt jwt){return result.contextWrite(ReactiveSecurityContextHolder.withAuthentication(new JwtAuthenticationToken(jwt,List.of())));}
    @Test void actualNativeGrantCarriesTheOriginalSubjectAndReturnsACallerOwnedGeneratedClient(){when(decoder.decode("synthetic-exchanged-token")).thenReturn(Mono.just(target()));var client=context(factory().requireCurrent(permit),inbound()).block(Duration.ofSeconds(2));assertNotNull(client);assertSame(client.contracts().getApiClient(),client.parties().getApiClient());assertEquals(serverBinding,client.binding());assertEquals(1,calls.get());assertTrue(form.get().contains("subject_token=synthetic-subject-token"));assertTrue(form.get().contains("audience=contract-audience"));assertFalse(form.get().contains("actor_token="));var auth=assertInstanceOf(io.fireflysoftware.core.contract.sdk.invoker.auth.HttpBearerAuth.class,client.contracts().getApiClient().getAuthentication("contractReadBearer"));assertEquals("synthetic-exchanged-token",auth.getBearerToken());}
    @Test void missingNativeVerifiedContextCannotStartAnExchange(){StepVerifier.create(factory().requireCurrent(permit)).expectError(PolicyBindingRefusedException.class).verify();assertEquals(0,calls.get());verifyNoInteractions(decoder);}
    @Test void staffCannotBeRelabeledAsHuman(){StepVerifier.create(context(factory().requireCurrent(permit),jwt("staff","STAFF","opaque subject","policy-audience","inbound-client",now.plusSeconds(60)))).expectError(PolicyBindingRefusedException.class).verify();assertEquals(0,calls.get());}
    @Test void anotherReturnedSubjectIsRefusedBeforeClientPublication(){when(decoder.decode(anyString())).thenReturn(Mono.just(jwt("synthetic-exchanged-token","HUMAN","another subject","contract-audience","policy-contract-exchange",now.plusSeconds(30))));StepVerifier.create(context(factory().requireCurrent(permit),inbound())).expectError(PolicyBindingRefusedException.class).verify();assertEquals(1,calls.get());}
    @Test void anEmptyNativeDecoderCannotBecomeSuccessfulClientAcquisition(){when(decoder.decode(anyString())).thenReturn(Mono.empty());StepVerifier.create(context(factory().requireCurrent(permit),inbound())).expectError(PolicyBindingRefusedException.class).verify();}
    @Test void clientCredentialsCannotReplaceTheSubjectGrant(){assertThrows(ResponseStatusException.class,()->new ExchangedPolicyContractClientProviderImpl(registration(AuthorizationGrantType.CLIENT_CREDENTIALS),issuer,"contract-audience","client_id","policy-contract-exchange",serverBinding,decoder,clock,connector()));assertEquals(0,calls.get());}

    @Test void missingIssuedTokenTypeIsRefusedByTheActualProductionExtractor(){tokenReply.set(tokenReply.get().replace(",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"",""));StepVerifier.create(context(factory().requireCurrent(permit),inbound())).expectError(PolicyBindingRefusedException.class).verify();verifyNoInteractions(decoder);}
    @Test void errorAndTokenAmbiguityIsRefusedBeforeNativeDecoder(){tokenReply.set(tokenReply.get().replace("{","{\"error\":\"invalid_grant\","));StepVerifier.create(context(factory().requireCurrent(permit),inbound())).expectError(PolicyBindingRefusedException.class).verify();verifyNoInteractions(decoder);}
    @Test void wrongTargetAudienceCannotPublishAContractClient(){when(decoder.decode(anyString())).thenReturn(Mono.just(jwt("synthetic-exchanged-token","HUMAN","opaque subject","another-audience","policy-contract-exchange",now.plusSeconds(30))));StepVerifier.create(context(factory().requireCurrent(permit),inbound())).expectError(PolicyBindingRefusedException.class).verify();}
    @Test void mismatchedServerDatasetRefusesBeforeExchange(){var other=new PolicyContractClientProvider.ServerBinding(tenant,UUID.randomUUID(),1,"b".repeat(64),URI.create("https://contracts.invalid"),UUID.randomUUID(),now.plusSeconds(60));var provider=new ExchangedPolicyContractClientProviderImpl(registration(AuthorizationGrantType.TOKEN_EXCHANGE),issuer,"contract-audience","client_id","policy-contract-exchange",other,decoder,clock,connector());StepVerifier.create(context(provider.requireCurrent(permit),inbound())).expectError(PolicyBindingRefusedException.class).verify();assertEquals(0,calls.get());verifyNoInteractions(decoder);}
    @Test void originalMonotonicExpiryCannotStartExchange(){var expired=new PolicyBindingAdmission.Permit(permit.request(),tenant,party,permit.bindingId(),permit.bindingVersion(),permit.bindingDigest(),permit.actor(),permit.authorizationPolicyRevision(),permit.processId(),permit.correlationId(),now,System.nanoTime()-Duration.ofSeconds(10).toNanos(),now.plusSeconds(5));StepVerifier.create(context(factory().requireCurrent(expired),inbound())).expectError(PolicyBindingRefusedException.class).verify();assertEquals(0,calls.get());verifyNoInteractions(decoder);}
    @Test void twoOverlappingHumansKeepSeparateCallerBoundGeneratedCredentials(){
        var gate=reactor.core.publisher.Sinks.<Void>empty();responseGate.set(gate.asMono());
        UUID secondParty=UUID.randomUUID();var secondRequest=new io.fireflysoftware.core.insurance.policies.interfaces.binding.GovernedPolicyBindRequest(UUID.randomUUID(),UUID.randomUUID(),secondParty,UUID.randomUUID(),UUID.randomUUID(),1,1,UUID.randomUUID(),"a".repeat(64),"a".repeat(64),UUID.randomUUID(),"SANDBOX-2",java.time.LocalDate.of(2027,1,1),java.time.LocalDate.of(2028,1,1));
        var secondPermit=new PolicyBindingAdmission.Permit(PolicyBindingAdmission.Request.bind(secondRequest),tenant,secondParty,permit.bindingId(),permit.bindingVersion(),permit.bindingDigest(),new AuditActor(issuer,"opaque subject B","inbound-client",platformTenant,null,null),"policy-v1",UUID.randomUUID(),UUID.randomUUID(),now,System.nanoTime(),now.plusSeconds(5));
        var secondInbound=Jwt.withTokenValue("synthetic-subject-b").header("alg","RS256").issuer(issuer).subject("opaque subject B").claim("aud",List.of("policy-audience")).claim("client_id","inbound-client").claim("principal_kind","HUMAN").claim("tenant_id",platformTenant).claim("party_id",secondParty.toString()).claim("scope","insurance:policies:bind").issuedAt(now.minusSeconds(1)).notBefore(now.minusSeconds(1)).expiresAt(now.plusSeconds(60)).build();
        var secondTarget=Jwt.withTokenValue("synthetic-exchanged-b").header("alg","RS256").issuer(issuer).subject("opaque subject B").claim("aud",List.of("contract-audience")).claim("client_id","policy-contract-exchange").claim("principal_kind","HUMAN").claim("tenant_id",platformTenant).claim("party_id",secondParty.toString()).claim("scope","contracts:read contracts:parties:read").issuedAt(now.minusSeconds(1)).notBefore(now.minusSeconds(1)).expiresAt(now.plusSeconds(30)).build();
        when(decoder.decode("synthetic-exchanged-token")).thenReturn(Mono.just(target()));when(decoder.decode("synthetic-exchanged-b")).thenReturn(Mono.just(secondTarget));
        var provider=factory();
        StepVerifier.create(Mono.zip(context(provider.requireCurrent(permit),inbound()),context(provider.requireCurrent(secondPermit),secondInbound))).expectSubscription().then(()->assertEquals(2,calls.get())).then(()->gate.tryEmitEmpty()).assertNext(pair->{
            assertNotSame(pair.getT1().contracts().getApiClient(),pair.getT2().contracts().getApiClient());
            assertSame(pair.getT1().contracts().getApiClient(),pair.getT1().parties().getApiClient());assertSame(pair.getT2().contracts().getApiClient(),pair.getT2().parties().getApiClient());
            var left=assertInstanceOf(io.fireflysoftware.core.contract.sdk.invoker.auth.HttpBearerAuth.class,pair.getT1().contracts().getApiClient().getAuthentication("contractReadBearer"));
            var right=assertInstanceOf(io.fireflysoftware.core.contract.sdk.invoker.auth.HttpBearerAuth.class,pair.getT2().contracts().getApiClient().getAuthentication("contractReadBearer"));
            assertEquals("synthetic-exchanged-token",left.getBearerToken());assertEquals("synthetic-exchanged-b",right.getBearerToken());
        }).verifyComplete();
    }
}
