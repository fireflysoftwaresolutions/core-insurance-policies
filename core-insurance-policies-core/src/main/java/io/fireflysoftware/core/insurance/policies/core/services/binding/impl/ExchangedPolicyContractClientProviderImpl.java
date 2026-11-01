/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.core.services.binding.impl;

import io.fireflysoftware.core.insurance.policies.core.services.binding.*;
import io.fireflysoftware.core.contract.sdk.api.ContractsApi;
import io.fireflysoftware.core.contract.sdk.api.ContractPartiesApi;
import io.fireflysoftware.core.contract.sdk.invoker.ApiClient;
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
import org.springframework.security.oauth2.core.endpoint.DefaultMapOAuth2AccessTokenResponseConverter;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.web.reactive.function.BodyExtractors;
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
public final class ExchangedPolicyContractClientProviderImpl implements PolicyContractClientProvider {
    private static final Set<String> SCOPES=Set.of("contracts:read","contracts:parties:read");
    private final ClientRegistration registration;
    private final String issuer,audience,clientClaim,delegatingClient;
    private final PolicyContractClientProvider.ServerBinding binding;
    private final ReactiveJwtDecoder decoder;
    private final WebClientReactiveTokenExchangeTokenResponseClient exchange;
    private final Clock clock;
    public ExchangedPolicyContractClientProviderImpl(ClientRegistration registration,String issuer,String audience,
            String clientClaim,String delegatingClient,PolicyContractClientProvider.ServerBinding binding,ReactiveJwtDecoder decoder,Clock clock){
        this(registration,issuer,audience,clientClaim,delegatingClient,binding,decoder,clock,productionConnector(registration,issuer,audience,clientClaim,delegatingClient,Objects.requireNonNull(binding).endpoint()));
    }
    ExchangedPolicyContractClientProviderImpl(ClientRegistration registration,String issuer,String audience,
            String clientClaim,String delegatingClient,PolicyContractClientProvider.ServerBinding binding,ReactiveJwtDecoder decoder,Clock clock,
            org.springframework.http.client.reactive.ClientHttpConnector connector){
        this.registration=Objects.requireNonNull(registration);this.issuer=required(issuer);this.audience=required(audience);
        this.clientClaim=required(clientClaim);this.delegatingClient=required(delegatingClient);this.binding=Objects.requireNonNull(binding);https(binding.endpoint());
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
        var converter=new DefaultMapOAuth2AccessTokenResponseConverter();
        exchange.setBodyExtractor((message,context)->BodyExtractors.toMono(new ParameterizedTypeReference<Map<String,Object>>(){}).extract(message,new BodyExtractor.Context(){
            public List<HttpMessageReader<?>> messageReaders(){return context.messageReaders();}
            public Optional<ServerHttpResponse> serverResponse(){return context.serverResponse();}
            public Map<String,Object> hints(){var hints=new java.util.HashMap<String,Object>(context.hints());hints.put(Hints.SUPPRESS_LOGGING_HINT,true);return Map.copyOf(hints);}
        }).map(parameters->{
            if(parameters.containsKey("error") || !"urn:ietf:params:oauth:token-type:access_token".equals(parameters.get("issued_token_type")))throw unavailable();
            try {
                if(!com.nimbusds.oauth2.sdk.TokenResponse.parse(new net.minidev.json.JSONObject(parameters)).indicatesSuccess())throw unavailable();
            } catch(com.nimbusds.oauth2.sdk.ParseException invalid){throw unavailable();}
            return converter.convert(parameters);
        }));
    }
    @Override public Mono<PolicyContractClientProvider.Clients> requireCurrent(PolicyBindingAdmission.Permit permit){return Mono.defer(()->{
        binding(permit);
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
                                        binding(permit);
                                        ApiClient client=new ApiClient();client.setBasePath(binding.endpoint().toASCIIString());client.setBearerToken(token.getTokenValue());
                                        return new PolicyContractClientProvider.Clients(binding,new ContractsApi(client),new ContractPartiesApi(client));
                                    });
                            });
                    });
            });
    }).onErrorMap(error->new PolicyBindingRefusedException());}
    private void binding(PolicyBindingAdmission.Permit permit){
        permit.remaining(clock,System::nanoTime);
        if(!permit.resourceTenantId().equals(binding.resourceTenantId()) || !permit.bindingId().equals(binding.configurationBindingId())
                || permit.bindingVersion()!=binding.configurationBindingVersion() || !permit.bindingDigest().equals(binding.configurationBindingDigest())
                || !clock.instant().isBefore(binding.notAfter()) || permit.notAfter().isAfter(binding.notAfter()))throw unavailable();
    }
    private void subject(Jwt jwt,PolicyBindingAdmission.Permit permit,boolean target,Jwt original){
        permit.remaining(clock,System::nanoTime);var now=clock.instant();
        Object rawScope=jwt.getClaims().get("scope");
        boolean targetScope=rawScope instanceof String value && Set.copyOf(java.util.Arrays.asList(value.split(" ",-1))).equals(SCOPES);
        boolean originalScope=rawScope instanceof String value && Set.copyOf(java.util.Arrays.asList(value.split(" ",-1))).equals(Set.of(policyScope(permit)));
        if(!(target?targetScope:originalScope) || !issuer.equals(claim(jwt,"iss")) || !permit.actor().issuer().equals(claim(jwt,"iss"))
            || !permit.actor().subject().equals(claim(jwt,"sub")) || !target && !permit.actor().clientId().equals(claim(jwt,clientClaim))
            || !"HUMAN".equals(claim(jwt,"principal_kind"))
            || !Objects.equals(permit.partyId().toString(),claim(jwt,"party_id"))
            || !permit.actor().platformTenantId().equals(claim(jwt,"tenant_id"))
            || !(jwt.getClaims().get("exp") instanceof java.time.Instant) || !(jwt.getClaims().get("nbf") instanceof java.time.Instant)
            || jwt.getExpiresAt()==null || jwt.getNotBefore()==null || !jwt.getExpiresAt().isAfter(now) || jwt.getNotBefore().isAfter(now)
            || permit.notAfter().isAfter(jwt.getExpiresAt()) || target && (!(jwt.getClaims().get("aud") instanceof List<?> values) || values.size()!=1 || !(values.getFirst() instanceof String) || !audience.equals(values.getFirst())
                || !targetScope || !delegatingClient.equals(claim(jwt,clientClaim)) || jwt.getExpiresAt().isAfter(original.getExpiresAt())))throw unavailable();
    }
    private static String policyScope(PolicyBindingAdmission.Permit permit){return switch(permit.request().action()){
        case BIND -> "insurance:policies:bind";
        case ISSUE -> "insurance:policies:issue";
        case RECOVER -> throw unavailable();
    };}
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
    private static ResponseStatusException unavailable(){return new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Approved caller-bound contract token exchange unavailable");}
    @Override public String toString(){return "ExchangedPolicyContractClientProviderImpl[redacted]";}
}
