package io.fireflysoftware.core.insurance.policies.core.services.binding;

import io.fireflysoftware.core.insurance.policies.core.services.binding.impl.SandboxPolicyBindingAdmissionImpl;
import io.fireflysoftware.core.insurance.policies.interfaces.binding.PolicyBindingValues;
import java.net.URI;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Explicit first-sandbox deployment settings, never request authority or namespace inference. */
@ConfigurationProperties("insurance.policies.governed.runtime")
public record PolicyBindingRuntimeProperties(String connectionFactoryBean,SandboxPolicyBindingAdmissionImpl.Profile profile,
        URI jwkSetUri,URI pdpEndpoint,String pdpDecisionPath,UUID policyholderRoleId,Instant bindingNotAfter,
        Target contracts,Target quotes) {
    public PolicyBindingRuntimeProperties {
        connectionFactoryBean=PolicyBindingValues.text(connectionFactoryBean,128);
        if(!connectionFactoryBean.matches("[A-Za-z][A-Za-z0-9._-]{0,127}"))throw invalid();
        Objects.requireNonNull(profile);https(jwkSetUri);https(pdpEndpoint);
        pdpDecisionPath=PolicyBindingValues.text(pdpDecisionPath,255);
        if(!pdpDecisionPath.matches("[A-Za-z0-9_]+(/[A-Za-z0-9_]+)*"))throw invalid();
        PolicyBindingValues.id(policyholderRoleId);Objects.requireNonNull(bindingNotAfter);Objects.requireNonNull(contracts);Objects.requireNonNull(quotes);
    }
    public PolicyContractClientProvider.ServerBinding contractBinding(){
        return new PolicyContractClientProvider.ServerBinding(profile.resourceTenantId(),profile.configurationBindingId(),profile.configurationBindingVersion(),
                profile.configurationBindingDigest(),contracts.endpoint(),policyholderRoleId,bindingNotAfter);
    }
    public record Target(URI endpoint,URI tokenEndpoint,String audience,String clientId,String clientSecret,String delegatingClientId) {
        public Target {
            https(endpoint);https(tokenEndpoint);audience=PolicyBindingValues.text(audience,255);clientId=PolicyBindingValues.text(clientId,255);
            delegatingClientId=PolicyBindingValues.text(delegatingClientId,255);
            if(clientSecret==null || clientSecret.isBlank() || clientSecret.length()>4096)throw invalid();
        }
        @Override public String toString(){return "PolicyOAuthTarget[redacted]";}
    }
    private static void https(URI uri){
        if(uri==null || !"https".equals(uri.getScheme()) || uri.getHost()==null || uri.getUserInfo()!=null || uri.getQuery()!=null || uri.getFragment()!=null)throw invalid();
    }
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("Explicit governed policy runtime configuration required");}
    @Override public String toString(){return "PolicyRuntimeProperties[redacted]";}
}
