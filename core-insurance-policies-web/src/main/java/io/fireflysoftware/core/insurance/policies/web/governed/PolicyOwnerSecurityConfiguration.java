package io.fireflysoftware.core.insurance.policies.web.governed;

import io.fireflysoftware.core.insurance.policies.interfaces.binding.PolicyBindingValues;
import org.fireflyframework.security.core.context.PrincipalFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authorization.AuthenticatedReactiveAuthorizationManager;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.oauth2.server.resource.web.server.BearerTokenServerAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.security.web.server.authorization.AuthorizationWebFilter;
import org.springframework.security.web.server.authorization.ExceptionTranslationWebFilter;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import reactor.core.publisher.Mono;

/** No SecurityWebFilterChain bean is added, so existing global chain backoff is not triggered. */
@Configuration(proxyBeanMethods=false)
@ConditionalOnProperty(prefix="insurance.policies.governed",name={"enabled","runtime.enabled"},havingValue="true")
public class PolicyOwnerSecurityConfiguration {
    @Bean @Order(-60)
    PolicyOwnerRouteGuardWebFilterImpl policyOwnerOnlyRoutes(){return new PolicyOwnerRouteGuardWebFilterImpl();}
    @Bean @Order(-55)
    ExceptionTranslationWebFilter policyOwnerExceptionTranslation(){
        var filter=new ExceptionTranslationWebFilter();filter.setAuthenticationEntryPoint(new BearerTokenServerAuthenticationEntryPoint());return filter;
    }
    @Bean @Order(-50)
    AuthenticationWebFilter policyOwnerAuthentication(@Qualifier("policyBindingReceiverDecoder") ReactiveJwtDecoder decoder,
            @Qualifier("policyBindingPrincipalFactory") PrincipalFactory principals){
        var manager=new JwtReactiveAuthenticationManager(decoder);
        manager.setJwtAuthenticationConverter(jwt->Mono.fromSupplier(()->{
            Object raw=jwt.getClaims().get("tenant_id");
            if(!(raw instanceof String tenant))throw invalid();
            try{PolicyBindingValues.text(tenant,255);}catch(RuntimeException malformed){throw invalid();}
            var principal=principals.fromClaims(jwt.getSubject(),jwt.getIssuer().toString(),jwt.getClaims()).toBuilder().tenantId(tenant).build();
            // The supported native token retains both verified JWT and the library's rich principal.
            return new JwtAuthenticationToken(jwt,principal,principal.authorities().stream().map(SimpleGrantedAuthority::new).toList());
        }));
        var filter=new AuthenticationWebFilter(manager);filter.setServerAuthenticationConverter(new ServerBearerTokenAuthenticationConverter());
        filter.setRequiresAuthenticationMatcher(PolicyOwnerRouteGuardWebFilterImpl.SUPPORTED);
        filter.setSecurityContextRepository(NoOpServerSecurityContextRepository.getInstance());
        filter.setAuthenticationFailureHandler(new ServerAuthenticationEntryPointFailureHandler(new BearerTokenServerAuthenticationEntryPoint()));
        return filter;
    }
    private static org.springframework.security.oauth2.core.OAuth2AuthenticationException invalid(){return new org.springframework.security.oauth2.core.OAuth2AuthenticationException(new org.springframework.security.oauth2.core.OAuth2Error("invalid_token","Exact signed tenant claim required",null));}
    @Bean @Order(-40)
    AuthorizationWebFilter policyOwnerAuthorization(){return new AuthorizationWebFilter(AuthenticatedReactiveAuthorizationManager.authenticated());}
}
