/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.core.services.binding.impl;

import io.fireflysoftware.core.insurance.policies.core.services.binding.*;
import io.fireflysoftware.core.insurance.underwriting.sdk.api.GovernedQuoteOffersApi;
import io.fireflysoftware.core.insurance.underwriting.sdk.invoker.ApiClient;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.springframework.core.codec.Hints;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.reactive.JdkClientHttpConnector;
import org.springframework.http.codec.HttpMessageReader;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.endpoint.TokenExchangeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveTokenExchangeTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.web.reactive.function.OAuth2BodyExtractors;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.reactive.function.BodyExtractor;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

/** Uses the supported native grant with the original verified HUMAN subject; no machine-subject substitution. */
public final class ExchangedAcceptedQuoteClientProviderImpl implements AcceptedQuoteClientProvider {
    private static final Set<String> SCOPES=Set.of("insurance:quotes:read","insurance:quotes:recover");
    private final ClientRegistration registration;
    private final String issuer,audience,clientClaim,delegatingClient;
    private final URI endpoint;
    private final ReactiveJwtDecoder decoder;
    private final WebClientReactiveTokenExchangeTokenResponseClient exchange;
    private final Clock clock;
    public ExchangedAcceptedQuoteClientProviderImpl(ClientRegistration registration,String issuer,String audience,
            String clientClaim,String delegatingClient,URI endpoint,ReactiveJwtDecoder decoder,Clock clock){
        this(registration,issuer,audience,clientClaim,delegatingClient,endpoint,decoder,clock,productionConnector(registration,issuer,audience,clientClaim,delegatingClient,endpoint));
    }
    ExchangedAcceptedQuoteClientProviderImpl(ClientRegistration registration,String issuer,String audience,
            String clientClaim,String delegatingClient,URI endpoint,ReactiveJwtDecoder decoder,Clock clock,
            org.springframework.http.client.reactive.ClientHttpConnector connector){
        this.registration=Objects.requireNonNull(registration);this.issuer=required(issuer);this.audience=required(audience);
        this.clientClaim=required(clientClaim);this.delegatingClient=required(delegatingClient);this.endpoint=https(endpoint);
        this.decoder=Objects.requireNonNull(decoder);this.clock=Objects.requireNonNull(clock);
        tokenEndpoint(registration);
        if(!AuthorizationGrantType.TOKEN_EXCHANGE.equals(registration.getAuthorizationGrantType())
                || !ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(registration.getClientAuthenticationMethod())
                || registration.getClientSecret()==null || registration.getClientSecret().isBlank() || registration.getClientSecret().length()>4096
                || !SCOPES.equals(registration.getScopes()) || !clientClaim.matches("[A-Za-z][A-Za-z0-9_:.]{0,63}")
                || Set.of("sub","iss","aud","exp","nbf","party_id","principal_kind","tenant_id").contains(clientClaim))throw unavailable();
        exchange=new WebClientReactiveTokenExchangeTokenResponseClient();
        var strategies=ExchangeStrategies.builder().codecs(codecs->{codecs.defaultCodecs().maxInMemorySize(16384);codecs.defaultCodecs().enableLoggingRequestDetails(false);}).build();
        var transport=WebClient.builder().clientConnector(Objects.requireNonNull(connector))
            .exchangeStrategies(strategies).filter((request,next)->next.exchange(request).flatMap(response->
                response.statusCode().is2xxSuccessful()?Mono.just(response):response.releaseBody().then(Mono.error(unavailable())))).build();
        exchange.setWebClient(transport);
        exchange.addParametersConverter(request->{var values=new LinkedMultiValueMap<String,String>();values.set("audience",audience);return values;});
        exchange.setBodyExtractor((message,context)->OAuth2BodyExtractors.oauth2AccessTokenResponse().extract(message,new BodyExtractor.Context(){
            public List<HttpMessageReader<?>> messageReaders(){return context.messageReaders();}
            public Optional<ServerHttpResponse> serverResponse(){return context.serverResponse();}
            public Map<String,Object> hints(){var hints=new java.util.HashMap<String,Object>(context.hints());hints.put(Hints.SUPPRESS_LOGGING_HINT,true);return Map.copyOf(hints);}
        }));
    }
    @Override public Mono<GovernedQuoteOffersApi> requireExchangedClient(PolicyBindingAdmission.Permit permit){return Mono.defer(()->{
        permit.remaining(clock,System::nanoTime);
        return ReactiveSecurityContextHolder.getContext().map(context->context.getAuthentication())
            .filter(auth->auth instanceof JwtAuthenticationToken && auth.isAuthenticated()).cast(JwtAuthenticationToken.class)
            .switchIfEmpty(Mono.error(unavailable())).flatMap(authentication->{
                Jwt original=authentication.getToken();subject(original,permit,false,null);
                return exchange.getTokenResponse(new TokenExchangeGrantRequest(registration,original,null))
                    .timeout(permit.remaining(clock,System::nanoTime)).switchIfEmpty(Mono.error(unavailable())).flatMap(response->{
                        OAuth2AccessToken token=response.getAccessToken();
                        if(token==null || !OAuth2AccessToken.TokenType.BEARER.equals(token.getTokenType()) || token.getTokenValue().isBlank()
                                || !SCOPES.equals(token.getScopes()))return Mono.error(unavailable());
                        return decoder.decode(token.getTokenValue()).timeout(permit.remaining(clock,System::nanoTime)).switchIfEmpty(Mono.error(unavailable()))
                            .flatMap(exchanged->{
                                if(!token.getTokenValue().equals(exchanged.getTokenValue()))return Mono.error(unavailable());
                                subject(exchanged,permit,true,original);
                                return ReactiveSecurityContextHolder.getContext().filter(current->current.getAuthentication()==authentication)
                                    .switchIfEmpty(Mono.error(unavailable())).map(ignored->{
                                        permit.remaining(clock,System::nanoTime);
                                        ApiClient client=new ApiClient();client.setBasePath(endpoint.toASCIIString());client.setBearerToken(token.getTokenValue());
                                        return new GovernedQuoteOffersApi(client);
                                    });
                            });
                    });
            });
    }).onErrorMap(error->new PolicyBindingRefusedException());}
    private void subject(Jwt jwt,PolicyBindingAdmission.Permit permit,boolean target,Jwt original){
        permit.remaining(clock,System::nanoTime);var now=clock.instant();
        Object rawScope=jwt.getClaims().get("scope");
        boolean targetScope=rawScope instanceof String value && Set.copyOf(java.util.Arrays.asList(value.split(" ",-1))).equals(SCOPES);
        boolean originalScope=rawScope instanceof String value && Set.copyOf(java.util.Arrays.asList(value.split(" ",-1))).containsAll(SCOPES);
        if(!originalScope || !issuer.equals(claim(jwt,"iss")) || !permit.actor().issuer().equals(claim(jwt,"iss"))
            || !permit.actor().subject().equals(claim(jwt,"sub")) || !"HUMAN".equals(claim(jwt,"principal_kind"))
            || !Objects.equals(permit.partyId().toString(),claim(jwt,"party_id"))
            || !permit.resourceTenantId().toString().equals(claim(jwt,"tenant_id"))
            || !permit.actor().platformTenantId().equals(claim(jwt,"tenant_id"))
            || !(jwt.getClaims().get("exp") instanceof java.time.Instant) || !(jwt.getClaims().get("nbf") instanceof java.time.Instant)
            || jwt.getExpiresAt()==null || jwt.getNotBefore()==null || !jwt.getExpiresAt().isAfter(now) || jwt.getNotBefore().isAfter(now)
            || permit.notAfter().isAfter(jwt.getExpiresAt()) || target && (!(jwt.getClaims().get("aud") instanceof List<?> values) || values.size()!=1 || !(values.getFirst() instanceof String) || !audience.equals(values.getFirst())
                || !targetScope || !delegatingClient.equals(claim(jwt,clientClaim)) || jwt.getExpiresAt().isAfter(original.getExpiresAt())))throw unavailable();
    }
    private static JdkClientHttpConnector productionConnector(ClientRegistration registration,String issuer,String audience,String clientClaim,String client,URI endpoint){
        Objects.requireNonNull(registration);required(issuer);required(audience);required(clientClaim);required(client);https(endpoint);tokenEndpoint(registration);
        if(!AuthorizationGrantType.TOKEN_EXCHANGE.equals(registration.getAuthorizationGrantType())
            || !ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(registration.getClientAuthenticationMethod())
            || registration.getClientSecret()==null || registration.getClientSecret().isBlank() || registration.getClientSecret().length()>4096
            || !SCOPES.equals(registration.getScopes()) || !clientClaim.matches("[A-Za-z][A-Za-z0-9_:.]{0,63}")
            || Set.of("sub","iss","aud","exp","nbf","party_id","principal_kind","tenant_id").contains(clientClaim))throw unavailable();
        return new JdkClientHttpConnector(HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(2)).build());
    }
    private static URI tokenEndpoint(ClientRegistration registration){try{return https(URI.create(registration.getProviderDetails().getTokenUri()));}catch(IllegalArgumentException error){throw unavailable();}}
    private static String claim(Jwt jwt,String name){Object value=jwt.getClaims().get(name);if(!(value instanceof String text))throw unavailable();return text;}
    private static URI https(URI uri){if(uri==null || !"https".equals(uri.getScheme()) || uri.getHost()==null || uri.getUserInfo()!=null || uri.getQuery()!=null || uri.getFragment()!=null)throw unavailable();return uri;}
    private static String required(String value){try{return io.fireflysoftware.core.insurance.policies.interfaces.binding.PolicyBindingValues.text(value,512);}catch(RuntimeException error){throw unavailable();}}
    private static ResponseStatusException unavailable(){return new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Approved caller-bound quote token exchange unavailable");}
    @Override public String toString(){return "ExchangedAcceptedQuoteClientProviderImpl[redacted]";}
}
