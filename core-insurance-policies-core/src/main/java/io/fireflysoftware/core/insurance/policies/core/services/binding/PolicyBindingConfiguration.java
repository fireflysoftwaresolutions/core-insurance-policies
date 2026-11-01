/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.core.services.binding;

import io.fireflysoftware.core.insurance.policies.core.services.binding.impl.*;
import java.time.Clock;
import java.util.UUID;
import org.fireflyframework.core.transaction.BoundedR2dbcResources;
import org.fireflyframework.core.transaction.CleanupPolicy;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.r2dbc.connection.R2dbcTransactionManager;
import org.springframework.r2dbc.core.DatabaseClient;

/** No default factory, authority, contract dataset, exchange client or installer is inferred. */
@Configuration(proxyBeanMethods=false)
@ConditionalOnProperty(prefix="insurance.policies.governed",name="enabled",havingValue="true")
@ConditionalOnBean(value={SandboxPolicyBindingAdmissionImpl.class,PolicyContractClientProvider.class,AcceptedQuoteClientProvider.class},
    name={"policyBindingResources","policyBindingClient","policyBindingTemplate","policyBindingTransactionManager","policyBindingCleanup"})
public class PolicyBindingConfiguration {
    @Bean PolicyBindingAuditRootImpl governedPolicyAuditRoot(@Qualifier("policyBindingResources") BoundedR2dbcResources resources,
            @Qualifier("policyBindingClient") DatabaseClient client,@Qualifier("policyBindingTemplate") R2dbcEntityTemplate template,
            @Qualifier("policyBindingTransactionManager") R2dbcTransactionManager manager,
            @Qualifier("policyBindingCleanup") CleanupPolicy cleanup,SandboxPolicyBindingAdmissionImpl authority){
        return new PolicyBindingAuditRootImpl(resources,client,template,manager,cleanup,authority,authority,Clock.systemUTC(),System::nanoTime);
    }
    @Bean PolicyBindingStore governedPolicyStore(@Qualifier("policyBindingTemplate") R2dbcEntityTemplate template,PolicyBindingAuditRootImpl root){
        return new SpringDataPolicyBindingStoreImpl(template,root,UUID::randomUUID);
    }
    @Bean PolicyContractPort governedPolicyContractPort(PolicyContractClientProvider clients){return new GeneratedSdkPolicyContractPortImpl(clients,Clock.systemUTC());}
    @Bean GovernedPolicyService governedPolicyService(SandboxPolicyBindingAdmissionImpl authority,@Qualifier("governedPolicyContractPort") PolicyContractPort contracts,
            AcceptedQuoteClientProvider clients,PolicyBindingStore store){
        return authority.scoped(new GovernedPolicyServiceImpl(authority,new GeneratedSdkAcceptedQuotePortImpl(clients),contracts,store,Clock.systemUTC()));
    }
}
