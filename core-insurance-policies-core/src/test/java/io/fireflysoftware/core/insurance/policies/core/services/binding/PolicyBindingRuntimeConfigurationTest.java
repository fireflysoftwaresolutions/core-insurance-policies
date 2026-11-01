package io.fireflysoftware.core.insurance.policies.core.services.binding;

import io.fireflysoftware.core.insurance.policies.core.services.binding.impl.SandboxPolicyBindingAdmissionImpl;
import io.fireflysoftware.core.insurance.policies.interfaces.binding.*;
import io.r2dbc.spi.*;
import java.net.URI;
import java.time.*;
import java.util.*;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.http.*;
import org.springframework.web.reactive.function.client.*;
import reactor.core.publisher.Mono;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class PolicyBindingRuntimeConfigurationTest {
    final UUID tenant=UUID.randomUUID(),party=UUID.randomUUID();
    final String issuer="https://synthetic-issuer.invalid";
    PolicyBindingRuntimeProperties settings(){
        var target=new PolicyBindingRuntimeProperties.Target(URI.create("https://synthetic-target.invalid"),URI.create(issuer+"/token"),"target","exchange","synthetic-private-secret","exchange");
        return new PolicyBindingRuntimeProperties("ownedPolicyFactory",new SandboxPolicyBindingAdmissionImpl.Profile(issuer,"policy","caller",tenant.toString(),tenant,UUID.randomUUID(),1,"a".repeat(64)),
                URI.create(issuer+"/jwks"),URI.create("https://synthetic-pdp.invalid"),"insurance/policy",UUID.randomUUID(),Instant.now().plusSeconds(60),target,target);
    }
    @Test void defaultOffDoesNotCreateBusinessServiceOrRequireConfiguration(){
        new ApplicationContextRunner().withUserConfiguration(PolicyBindingRuntimeConfiguration.class).run(context->{
            assertNull(context.getStartupFailure());assertEquals(0,context.getBeanNamesForType(GovernedPolicyService.class).length);
            assertEquals(0,context.getBeanNamesForType(PolicyBindingRuntimeProperties.class).length);
        });
    }
    @Test void missingNamedFactoryDoesNotBorrowAnotherFactory(){
        var beans=new DefaultListableBeanFactory();var unrelated=mock(ConnectionFactory.class);beans.registerSingleton("unrelated",unrelated);
        assertThrows(org.springframework.beans.factory.NoSuchBeanDefinitionException.class,()->new PolicyBindingRuntimeConfiguration().configuredGovernedPolicyService(settings(),beans));
        verifyNoInteractions(unrelated);
    }
    @Test void realOwnedGraphConstructsWithoutBusinessIoAndMissingAuthorityStillRefuses(){
        var beans=new DefaultListableBeanFactory();var factory=mock(ConnectionFactory.class);var metadata=mock(ConnectionFactoryMetadata.class);
        when(metadata.getName()).thenReturn("PostgreSQL");when(factory.getMetadata()).thenReturn(metadata);beans.registerSingleton("ownedPolicyFactory",factory);
        var service=new PolicyBindingRuntimeConfiguration().configuredGovernedPolicyService(settings(),beans);
        var request=new GovernedPolicyBindRequest(UUID.randomUUID(),UUID.randomUUID(),party,UUID.randomUUID(),UUID.randomUUID(),1,1,UUID.randomUUID(),"a".repeat(64),"b".repeat(64),UUID.randomUUID(),"SANDBOX-1",LocalDate.of(2027,1,1),LocalDate.of(2028,1,1));
        assertEquals(GovernedPolicyCommandResponse.Status.REFUSED,service.bind(request).block(Duration.ofSeconds(2)).status());
        verify(factory,never()).create();assertFalse(settings().toString().contains("synthetic-private-secret"));
    }
    @Test void actualConfiguredNimbusDecoderVerifiesSignatureAndRejectsAnotherAudience()throws Exception{
        RSAKey key=new RSAKeyGenerator(2048).keyID("controlled-key").generate();var now=Instant.now();
        var transport=WebClient.builder().exchangeFunction(request->{
            assertEquals(issuer+"/jwks",request.url().toASCIIString());
            return Mono.just(ClientResponse.create(HttpStatus.OK).header(HttpHeaders.CONTENT_TYPE,MediaType.APPLICATION_JSON_VALUE).body(new JWKSet(key.toPublicJWK()).toString()).build());
        }).build();
        var decoder=PolicyBindingRuntimeConfiguration.decoder(issuer,"policy",issuer+"/jwks",transport);
        String good=token(key,now,"policy"),wrong=token(key,now,"another");
        assertEquals("opaque subject",decoder.decode(good).block(Duration.ofSeconds(3)).getSubject());
        assertThrows(org.springframework.security.oauth2.jwt.JwtException.class,()->decoder.decode(wrong).block(Duration.ofSeconds(3)));
    }
    private String token(RSAKey key,Instant now,String audience)throws Exception{
        var claims=new JWTClaimsSet.Builder().issuer(issuer).subject("opaque subject").audience(audience).issueTime(Date.from(now.minusSeconds(1))).notBeforeTime(Date.from(now.minusSeconds(1))).expirationTime(Date.from(now.plusSeconds(60))).build();
        var signed=new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),claims);signed.sign(new RSASSASigner(key));return signed.serialize();
    }
}
