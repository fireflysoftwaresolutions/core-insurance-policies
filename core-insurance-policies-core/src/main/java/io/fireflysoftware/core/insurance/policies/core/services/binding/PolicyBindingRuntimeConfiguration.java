package io.fireflysoftware.core.insurance.policies.core.services.binding;

import io.fireflysoftware.core.insurance.policies.core.services.binding.impl.*;
import io.r2dbc.spi.ConnectionFactory;
import io.fireflysoftware.core.insurance.policies.models.config.R2dbcConfiguration;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.fireflyframework.core.transaction.BoundedR2dbcResources;
import org.fireflyframework.core.transaction.CleanupPolicy;
import org.fireflyframework.core.transaction.OwnedLeaseConnectionFactory;
import org.fireflyframework.security.adapter.opa.OpaPolicyEvaluationAdapter;
import org.fireflyframework.security.core.authority.AuthorityMappingProperties;
import org.fireflyframework.security.core.authority.ConfigurableAuthorityMapper;
import org.fireflyframework.security.core.context.PrincipalFactory;
import org.fireflyframework.security.webflux.context.ReactorSecurityContextAdapter;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.JdkClientHttpConnector;
import org.springframework.r2dbc.connection.R2dbcTransactionManager;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.data.r2dbc.core.DefaultReactiveDataAccessStrategy;
import org.springframework.data.r2dbc.dialect.PostgresDialect;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.reactive.function.client.WebClient;

/** This explicit owner-only mode builds a real graph; it does not install schemas or grant authority. */
@Configuration(proxyBeanMethods=false)
@ConditionalOnProperty(prefix="insurance.policies.governed",name={"enabled","runtime.enabled"},havingValue="true")
@EnableConfigurationProperties(PolicyBindingRuntimeProperties.class)
public class PolicyBindingRuntimeConfiguration {
    @Bean("policyBindingPrincipalFactory")
    PrincipalFactory policyBindingPrincipalFactory(){
        return new PrincipalFactory(new ConfigurableAuthorityMapper(new AuthorityMappingProperties(List.of("roles"),List.of("scope"),"")));
    }
    @Bean("policyBindingReceiverDecoder")
    ReactiveJwtDecoder policyBindingReceiverDecoder(PolicyBindingRuntimeProperties settings){
        return decoder(settings.profile().issuer(),settings.profile().audience(),settings.jwkSetUri().toASCIIString());
    }
    @Bean
    @ConditionalOnMissingBean(GovernedPolicyService.class)
    GovernedPolicyService configuredGovernedPolicyService(PolicyBindingRuntimeProperties settings,BeanFactory beans){
        var delegate=beans.getBean(settings.connectionFactoryBean(),ConnectionFactory.class);
        var factory=delegate instanceof OwnedLeaseConnectionFactory held?held:new OwnedLeaseConnectionFactory(delegate);
        var client=DatabaseClient.create(factory);var template=new R2dbcEntityTemplate(client,new DefaultReactiveDataAccessStrategy(PostgresDialect.INSTANCE,R2dbcConfiguration.policyEnumConverters()));
        var manager=new R2dbcTransactionManager(factory);var resources=BoundedR2dbcResources.verify(factory,client,template,manager);
        var pdp=new OpaPolicyEvaluationAdapter(quietTransport().mutate().baseUrl(settings.pdpEndpoint().toASCIIString()).build(),settings.pdpDecisionPath());
        var authority=new SandboxPolicyBindingAdmissionImpl(new ReactorSecurityContextAdapter(),pdp,settings.profile(),Clock.systemUTC(),System::nanoTime,UUID::randomUUID,settings.bindingNotAfter());
        var root=new PolicyBindingAuditRootImpl(resources,client,template,manager,new CleanupPolicy(Duration.ofSeconds(1),Duration.ofSeconds(1)),authority,authority,Clock.systemUTC(),System::nanoTime);
        var store=new SpringDataPolicyBindingStoreImpl(template,root,UUID::randomUUID);
        var contractTarget=settings.contracts();var quoteTarget=settings.quotes();
        var contracts=new ExchangedPolicyContractClientProviderImpl(registration("policy-contract",contractTarget,Set.of("contracts:read","contracts:parties:read")),
                settings.profile().issuer(),contractTarget.audience(),"client_id",contractTarget.delegatingClientId(),settings.contractBinding(),
                decoder(settings.profile().issuer(),contractTarget.audience(),settings.jwkSetUri().toASCIIString()),Clock.systemUTC());
        var quotes=new ExchangedAcceptedQuoteClientProviderImpl(registration("policy-quote",quoteTarget,Set.of("insurance:quotes:read","insurance:quotes:recover")),
                settings.profile().issuer(),quoteTarget.audience(),"client_id",quoteTarget.delegatingClientId(),quoteTarget.endpoint(),
                decoder(settings.profile().issuer(),quoteTarget.audience(),settings.jwkSetUri().toASCIIString()),Clock.systemUTC());
        return authority.scoped(new GovernedPolicyServiceImpl(authority,new GeneratedSdkAcceptedQuotePortImpl(quotes),new GeneratedSdkPolicyContractPortImpl(contracts,Clock.systemUTC()),store,Clock.systemUTC()));
    }
    private static ClientRegistration registration(String id,PolicyBindingRuntimeProperties.Target target,Set<String> scopes){
        return ClientRegistration.withRegistrationId(id).clientId(target.clientId()).clientSecret(target.clientSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .tokenUri(target.tokenEndpoint().toASCIIString()).scope(scopes).build();
    }
    private static ReactiveJwtDecoder decoder(String issuer,String audience,String jwks){return decoder(issuer,audience,jwks,quietTransport());}
    static ReactiveJwtDecoder decoder(String issuer,String audience,String jwks,WebClient transport){
        var decoder=NimbusReactiveJwtDecoder.withJwkSetUri(jwks).webClient(transport).build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer),new JwtTimestampValidator(Duration.ZERO),
                jwt->jwt.getAudience().size()==1 && audience.equals(jwt.getAudience().getFirst())?OAuth2TokenValidatorResult.success():
                        OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token","Exact policy target audience required",null))));
        return decoder;
    }
    private static WebClient quietTransport(){
        return WebClient.builder().clientConnector(new JdkClientHttpConnector(HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(2)).build()))
                .codecs(codecs->{codecs.defaultCodecs().maxInMemorySize(16384);codecs.defaultCodecs().enableLoggingRequestDetails(false);}).build();
    }
}
