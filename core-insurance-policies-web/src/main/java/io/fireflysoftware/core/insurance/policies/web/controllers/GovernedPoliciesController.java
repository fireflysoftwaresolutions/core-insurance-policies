/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.web.controllers;

import io.fireflysoftware.core.insurance.policies.core.services.binding.GovernedPolicyService;
import io.fireflysoftware.core.insurance.policies.core.services.binding.GovernedPolicyUnavailableException;
import io.fireflysoftware.core.insurance.policies.interfaces.binding.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.UUID;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import org.fireflyframework.web.idempotency.annotation.DisableIdempotency;

@RestController
@RequestMapping("/api/v1/policies")
@Tag(name="GovernedPolicies",description="Explicitly configured sandbox binding and local activation, not carrier issuance")
@SecurityScheme(name="bearerAuth",type=SecuritySchemeType.HTTP,scheme="bearer",bearerFormat="JWT")
@SecurityRequirement(name="bearerAuth")
@ApiResponses({@ApiResponse(responseCode="401",description="Verified identity required",content=@Content),
    @ApiResponse(responseCode="403",description="Current scoped authority refused",content=@Content),
    @ApiResponse(responseCode="503",description="Trusted governed policy service is not configured",content=@Content)})
public final class GovernedPoliciesController {
    private final ObjectProvider<GovernedPolicyService> services;
    public GovernedPoliciesController(ObjectProvider<GovernedPolicyService> services){this.services=services;}
    @Operation(operationId="bindGovernedPolicy",summary="Bind an accepted sandbox quote to an existing validated contract")
    @ApiResponse(responseCode="200",description="Exact command outcome; recover the same action if uncertain",
        content=@Content(mediaType=MediaType.APPLICATION_JSON_VALUE,schema=@Schema(implementation=GovernedPolicyCommandResponse.class)))
    @DisableIdempotency
    @PostMapping(value="/governed/bindings",consumes=MediaType.APPLICATION_JSON_VALUE,produces=MediaType.APPLICATION_JSON_VALUE)
    public Mono<GovernedPolicyCommandResponse> bind(@RequestBody GovernedPolicyBindRequest request){return Mono.defer(()->service().bind(request));}
    @Operation(operationId="recoverGovernedPolicyBinding",summary="Observe a retained binding or activation action without creating a new action")
    @ApiResponse(responseCode="200",description="Protected retained observation; absence is not a guarantee of no commit",
        content=@Content(mediaType=MediaType.APPLICATION_JSON_VALUE,schema=@Schema(implementation=GovernedPolicyRecoveryResponse.class)))
    @GetMapping(value="/governed/recovery/{actionId}",produces=MediaType.APPLICATION_JSON_VALUE)
    public Mono<GovernedPolicyRecoveryResponse> recover(@PathVariable UUID actionId,@RequestParam String intentDigest){return Mono.defer(()->service().recover(actionId,intentDigest));}
    @Operation(operationId="issueGovernedPolicy",summary="Activate a bound sandbox policy locally; no carrier or certificate effect")
    @ApiResponse(responseCode="200",description="Exact activation outcome bound to the original action",
        content=@Content(mediaType=MediaType.APPLICATION_JSON_VALUE,schema=@Schema(implementation=GovernedPolicyCommandResponse.class)))
    @DisableIdempotency
    @PostMapping(value="/{policyId}/governed/issue",consumes=MediaType.APPLICATION_JSON_VALUE,produces=MediaType.APPLICATION_JSON_VALUE)
    public Mono<GovernedPolicyCommandResponse> issue(@PathVariable UUID policyId,@RequestBody GovernedPolicyIssueRequest request){return Mono.defer(()->service().issue(policyId,request));}
    private GovernedPolicyService service(){var service=services.getIfAvailable();if(service==null)throw new GovernedPolicyUnavailableException();return service;}
}
