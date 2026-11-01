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
class ExchangedAcceptedQuoteClientProviderTest {
    final Instant now=Instant.parse("2026-10-31T12:00:00Z");final Clock clock=Clock.fixed(now,ZoneOffset.UTC);
    final UUID tenant=UUID.randomUUID(),party=UUID.randomUUID(),action=UUID.randomUUID();final String issuer="https://synthetic-issuer.invalid";final String platformTenant="synthetic:opaque:policy-tenant";
    final AtomicInteger calls=new AtomicInteger();final AtomicReference<String> form=new AtomicReference<>();final ReactiveJwtDecoder decoder=mock(ReactiveJwtDecoder.class);
    final io.fireflysoftware.core.insurance.policies.interfaces.binding.GovernedPolicyBindRequest bindingRequest=new io.fireflysoftware.core.insurance.policies.interfaces.binding.GovernedPolicyBindRequest(action,UUID.randomUUID(),party,UUID.randomUUID(),UUID.randomUUID(),1,1,UUID.randomUUID(),"a".repeat(64),"a".repeat(64),UUID.randomUUID(),"SANDBOX-1",java.time.LocalDate.of(2027,1,1),java.time.LocalDate.of(2028,1,1));
    final PolicyBindingAdmission.Permit permit=new PolicyBindingAdmission.Permit(PolicyBindingAdmission.Request.bind(bindingRequest),tenant,party,UUID.randomUUID(),1,"b".repeat(64),new AuditActor(issuer,"opaque subject","inbound-client",platformTenant,null,null),"policy-v1",UUID.randomUUID(),UUID.randomUUID(),now,System.nanoTime(),now.plusSeconds(5));
    final AtomicReference<String> tokenReply=new AtomicReference<>("{\"access_token\":\"synthetic-exchanged-token\",\"token_type\":\"Bearer\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\",\"expires_in\":30,\"scope\":\"insurance:quotes:read insurance:quotes:recover\"}");
    Jwt jwt(String value,String kind,String subject,String audience,String client,Instant expiry){return Jwt.withTokenValue(value).header("alg","RS256").issuer(issuer).subject(subject).claim("aud",List.of(audience)).claim("client_id",client).claim("principal_kind",kind).claim("tenant_id",platformTenant).claim("party_id",party.toString()).claim("scope","policy-audience".equals(audience)?"insurance:policies:bind":"insurance:quotes:read insurance:quotes:recover").issuedAt(now.minusSeconds(1)).notBefore(now.minusSeconds(1)).expiresAt(expiry).build();}
    Jwt inbound(){return jwt("synthetic-subject-token","HUMAN","opaque subject","policy-audience","inbound-client",now.plusSeconds(60));}
    Jwt target(){return jwt("synthetic-exchanged-token","HUMAN","opaque subject","underwriting-audience","policy-exchange",now.plusSeconds(30));}
    ClientRegistration registration(AuthorizationGrantType grant){return ClientRegistration.withRegistrationId("owned-exchange").clientId("policy-exchange").clientSecret("synthetic-secret").clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).authorizationGrantType(grant).tokenUri(issuer+"/token").scope("insurance:quotes:read","insurance:quotes:recover").build();}
    ClientHttpConnector connector(){return (method,uri,callback)->{calls.incrementAndGet();var request=new MockClientHttpRequest(method,uri);return callback.apply(request).then(Mono.defer(request::getBodyAsString).flatMap(body->{form.set(body);var response=new MockClientHttpResponse(HttpStatus.OK);response.getHeaders().setContentType(MediaType.APPLICATION_JSON);response.setBody(tokenReply.get());return Mono.<ClientHttpResponse>just(response);}));};}
    ExchangedAcceptedQuoteClientProviderImpl factory(){return new ExchangedAcceptedQuoteClientProviderImpl(registration(AuthorizationGrantType.TOKEN_EXCHANGE),issuer,"underwriting-audience","client_id","policy-exchange",URI.create("https://underwriting.invalid"),decoder,clock,connector());}
    <T> Mono<T> context(Mono<T> result,Jwt jwt){return result.contextWrite(ReactiveSecurityContextHolder.withAuthentication(new JwtAuthenticationToken(jwt,List.of())));}
    @Test void actualNativeGrantCarriesTheOriginalSubjectAndReturnsACallerOwnedGeneratedClient(){when(decoder.decode("synthetic-exchanged-token")).thenReturn(Mono.just(target()));var client=context(factory().requireExchangedClient(permit),inbound()).block(Duration.ofSeconds(2));assertNotNull(client);assertEquals(1,calls.get());assertTrue(form.get().contains("subject_token=synthetic-subject-token"));assertTrue(form.get().contains("audience=underwriting-audience"));assertFalse(form.get().contains("actor_token="));var auth=assertInstanceOf(io.fireflysoftware.core.insurance.underwriting.sdk.invoker.auth.HttpBearerAuth.class,client.getApiClient().getAuthentication("governedQuoteBearer"));assertEquals("synthetic-exchanged-token",auth.getBearerToken());}
    @Test void missingNativeVerifiedContextCannotStartAnExchange(){StepVerifier.create(factory().requireExchangedClient(permit)).expectError(PolicyBindingRefusedException.class).verify();assertEquals(0,calls.get());verifyNoInteractions(decoder);}
    @Test void staffCannotBeRelabeledAsHuman(){StepVerifier.create(context(factory().requireExchangedClient(permit),jwt("staff","STAFF","opaque subject","policy-audience","inbound-client",now.plusSeconds(60)))).expectError(PolicyBindingRefusedException.class).verify();assertEquals(0,calls.get());}
    @Test void anotherReturnedSubjectIsRefusedBeforeClientPublication(){when(decoder.decode(anyString())).thenReturn(Mono.just(jwt("synthetic-exchanged-token","HUMAN","another subject","underwriting-audience","policy-exchange",now.plusSeconds(30))));StepVerifier.create(context(factory().requireExchangedClient(permit),inbound())).expectError(PolicyBindingRefusedException.class).verify();assertEquals(1,calls.get());}
    @Test void anEmptyNativeDecoderCannotBecomeSuccessfulClientAcquisition(){when(decoder.decode(anyString())).thenReturn(Mono.empty());StepVerifier.create(context(factory().requireExchangedClient(permit),inbound())).expectError(PolicyBindingRefusedException.class).verify();}
    @Test void clientCredentialsCannotReplaceTheSubjectGrant(){assertThrows(ResponseStatusException.class,()->new ExchangedAcceptedQuoteClientProviderImpl(registration(AuthorizationGrantType.CLIENT_CREDENTIALS),issuer,"underwriting-audience","client_id","policy-exchange",URI.create("https://underwriting.invalid"),decoder,clock,connector()));assertEquals(0,calls.get());}
}
