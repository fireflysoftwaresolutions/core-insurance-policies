/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.core.services.binding.impl;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.fireflysoftware.core.insurance.policies.core.services.binding.*;
import io.fireflysoftware.core.insurance.policies.interfaces.binding.*;
import io.fireflysoftware.core.insurance.policies.interfaces.enums.*;
import io.fireflysoftware.core.insurance.policies.models.binding.*;
import io.fireflysoftware.core.insurance.policies.models.entities.*;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.data.r2dbc.core.StatementMapper;
import org.springframework.data.r2dbc.repository.support.R2dbcRepositoryFactory;
import org.springframework.data.relational.core.query.Criteria;
import org.springframework.data.relational.core.query.Query;
import org.springframework.data.relational.core.query.Update;
import reactor.core.publisher.Mono;

/** Assigned inserts and scoped compare-and-set effects; every method requires the owner-installed protocol. */
public final class SpringDataPolicyBindingStoreImpl implements PolicyBindingStore {
    private final R2dbcEntityTemplate template;
    private final PolicyBindingAuditRootImpl root;
    private final PolicyBindingRepositories.Operations operations;
    private final PolicyBindingRepositories.Bindings bindings;
    private final PolicyBindingRepositories.Receipts receipts;
    private final PolicyBindingNativeIntegrity integrity;
    private final Supplier<UUID> ids;
    private final ObjectMapper json=new ObjectMapper(JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(20).maxStringLength(65536).build()).build());
    public SpringDataPolicyBindingStoreImpl(R2dbcEntityTemplate template,PolicyBindingAuditRootImpl root,Supplier<UUID> ids){
        this.template=Objects.requireNonNull(template);this.root=Objects.requireNonNull(root);root.requireTemplate(template);this.ids=Objects.requireNonNull(ids);
        var factory=new R2dbcRepositoryFactory(template);operations=factory.getRepository(PolicyBindingRepositories.Operations.class);
        bindings=factory.getRepository(PolicyBindingRepositories.Bindings.class);receipts=factory.getRepository(PolicyBindingRepositories.Receipts.class);
        integrity=factory.getRepository(PolicyBindingNativeIntegrity.class);
    }
    @Override public Mono<GovernedPolicyCommandResponse> bind(PolicyBindingAdmission.Permit permit,GovernedPolicyBindRequest request,AcceptedQuoteEvidence quote){return Mono.defer(()->{
        require(permit,PolicyBindingAdmission.Action.BIND,request.actionId(),request.intentDigest(),null);quote.requireMatch(permit,request);
        UUID policyId=id(),eventId=id();String businessDigest=PolicyBindingValues.hash("CORE_POLICY_BIND_EFFECT_V1",permit.resourceTenantId().toString(),request.intentDigest(),quote.snapshotDigest());
        return root.execute(permit,policyId,eventId,"insurance.sandbox.policy.bind",()->businessDigest,()->null,
            ()->protocol().then(retained(permit,request.actionId(),request.intentDigest())),effect->{
                var record=effect.record();var time=LocalDateTime.ofInstant(record.recordedAt(),ZoneOffset.UTC);
                UUID operationId=id(),receiptId=id(),transactionId=id();
                String receiptDigest=receiptDigest(permit,request.actionId(),request.intentDigest(),policyId,PolicyStatus.BOUND,1,quote.acceptanceId(),quote.termsDigest(),record.recordHash());
                var result=new GovernedPolicyBindingResult(policyId,request.policyNumber(),PolicyStatus.BOUND,1,receiptDigest,
                        quote.acceptanceActionId(),quote.acceptanceId(),quote.offerId(),quote.offerVersion(),quote.termsDigest());
                var snapshot=new PolicyBindingSnapshot(policyId,permit.resourceTenantId(),permit.actor().issuer(),permit.actor().subject(),
                    request.submissionId(),request.partyId(),request.productId(),request.contractId(),request.policyNumber(),quote.currency(),
                    request.inceptionDate(),request.expiryDate(),quote.offerId(),quote.offerVersion(),quote.controlGeneration(),quote.acceptanceActionId(),
                    quote.acceptanceId(),quote.acceptanceIntentDigest(),quote.termsDigest(),quote.acceptedAt(),quote.snapshotDigest(),quote.productRevisionId(),quote.productDigest(),quote.riskDigest(),
                    quote.providerVersion(),quote.ruleSetVersion(),quote.basePremium(),quote.tax(),quote.fees(),encode(quote.coverageTerms()),"BOUND",1,receiptDigest,eventId,null);
                var policy=Policy.builder().policyId(policyId).tenantId(permit.resourceTenantId()).contractId(request.contractId()).productId(request.productId())
                    .policyNumber(request.policyNumber()).lineOfBusiness(LineOfBusiness.PROPERTY).policyStatus(PolicyStatus.BOUND).currency(quote.currency())
                    .inceptionDate(request.inceptionDate()).expiryDate(request.expiryDate()).createdAt(time).updatedAt(time).build();
                var party=PolicyParty.builder().policyPartyId(id()).policyId(policyId).partyId(request.partyId()).role(PolicyPartyRole.POLICYHOLDER)
                    .effectiveFrom(request.inceptionDate()).effectiveTo(request.expiryDate()).active(true).createdAt(time).updatedAt(time).build();
                var transaction=PolicyTransaction.builder().policyTransactionId(transactionId).policyId(policyId).transactionNumber("NB-"+request.actionId())
                    .transactionType(PolicyTransactionType.NEW_BUSINESS).transactionStatus(PolicyTransactionStatus.BOUND).effectiveDate(request.inceptionDate())
                    .expiryDate(request.expiryDate()).sequenceNumber(1).outOfSequence(false).createdAt(time).updatedAt(time).build();
                var coverage=Coverage.builder().coverageId(id()).policyId(policyId).policyTransactionId(transactionId).coverageCode("SANDBOX_PROPERTY_DAMAGE")
                    .coverageName("Illustrative sandbox property record; no carrier coverage issuance").limitAmount(amount(quote,"insuredLimit"))
                    .deductibleAmount(amount(quote,"deductible")).currency(quote.currency()).premiumAmount(quote.basePremium()).createdAt(time).updatedAt(time).build();
                return insert(policy).then(insert(party)).then(insert(transaction)).then(insert(coverage)).then(history(policyId,PolicyStatus.BOUND,time))
                    .then(insert(snapshot)).then(retain(permit,request.actionId(),request.intentDigest(),operationId,receiptId,result,effect))
                    .thenReturn(committed(request.actionId(),request.intentDigest(),result));
            });
    });}
    @Override public Mono<GovernedPolicyCommandResponse> issue(PolicyBindingAdmission.Permit permit,UUID policyId,GovernedPolicyIssueRequest request){return Mono.defer(()->{
        String digest=request.intentDigest(policyId);require(permit,PolicyBindingAdmission.Action.ISSUE,request.actionId(),digest,policyId);
        var selected=new AtomicReference<PolicyBindingSnapshot>();UUID eventId=id();
        return root.execute(permit,policyId,eventId,"insurance.sandbox.policy.activate",
            ()->PolicyBindingValues.hash("CORE_POLICY_ACTIVATE_EFFECT_V1",permit.resourceTenantId().toString(),digest,selected.get().quoteSnapshotDigest()),
            ()->selected.get().boundEventId(),()->protocol().then(retained(permit,request.actionId(),digest)).flatMap(existing->{
                if(existing.isPresent())return Mono.just(existing);
                return bindings.findByTenantIdAndOwnerIssuerAndOwnerSubjectAndPolicyId(permit.resourceTenantId(),permit.actor().issuer(),permit.actor().subject(),policyId)
                    .switchIfEmpty(Mono.error(refused())).map(row->{
                        if(!row.partyId().equals(permit.partyId()) || !"BOUND".equals(row.state()) || row.bindingVersion()!=request.expectedBindingVersion()
                                || !request.bindingReceiptDigest().equals(row.bindingReceiptDigest()))throw refused();
                        selected.set(row);return Optional.<GovernedPolicyCommandResponse>empty();
                    });
            }),effect->{
                var row=selected.get();long version=Math.addExact(row.bindingVersion(),1);var record=effect.record();
                var time=LocalDateTime.ofInstant(record.recordedAt(),ZoneOffset.UTC);
                String receiptDigest=receiptDigest(permit,request.actionId(),digest,policyId,PolicyStatus.IN_FORCE,version,row.acceptanceId(),row.termsDigest(),record.recordHash());
                var result=new GovernedPolicyBindingResult(policyId,row.policyNumber(),PolicyStatus.IN_FORCE,version,receiptDigest,row.acceptanceActionId(),row.acceptanceId(),row.offerId(),row.offerVersion(),row.termsDigest());
                Criteria policy=Criteria.where("policyId").is(policyId).and("tenantId").is(permit.resourceTenantId()).and("policyStatus").is(PolicyStatus.BOUND)
                    .and("contractId").is(row.contractId()).and("productId").is(row.productId()).and("policyNumber").is(row.policyNumber())
                    .and("lineOfBusiness").is(LineOfBusiness.PROPERTY).and("currency").is(row.currency()).and("inceptionDate").is(row.inceptionDate()).and("expiryDate").is(row.expiryDate());
                Criteria binding=Criteria.where("policyId").is(policyId).and("tenantId").is(permit.resourceTenantId()).and("ownerIssuer").is(permit.actor().issuer())
                    .and("ownerSubject").is(permit.actor().subject()).and("state").is("BOUND").and("bindingVersion").is(row.bindingVersion())
                    .and("bindingReceiptDigest").is(row.bindingReceiptDigest()).and("quoteSnapshotDigest").is(row.quoteSnapshotDigest());
                return one(template.update(Policy.class).matching(Query.query(policy)).apply(Update.update("policyStatus",PolicyStatus.IN_FORCE).set("updatedAt",time)))
                    .then(one(template.update(PolicyBindingSnapshot.class).matching(Query.query(binding)).apply(Update.update("state","IN_FORCE")
                        .set("bindingVersion",version).set("bindingReceiptDigest",receiptDigest).set("activeEventId",eventId))))
                    .then(history(policyId,PolicyStatus.IN_FORCE,time)).then(retain(permit,request.actionId(),digest,id(),id(),result,effect))
                    .thenReturn(committed(request.actionId(),digest,result));
            });
    });}
    @Override public Mono<GovernedPolicyRecoveryResponse> recover(PolicyBindingAdmission.Permit permit,UUID actionId,String digest){return Mono.defer(()->{
        require(permit,PolicyBindingAdmission.Action.RECOVER,actionId,digest,null);
        return root.read(permit,()->protocol().then(retained(permit,actionId,digest)).map(value->{
            if(value.isEmpty())return new GovernedPolicyRecoveryResponse(GovernedPolicyRecoveryResponse.State.NOT_OBSERVED_AT_THIS_READ,actionId,digest,null);
            var command=value.orElseThrow();return command.status()==GovernedPolicyCommandResponse.Status.COMMITTED
                ?new GovernedPolicyRecoveryResponse(GovernedPolicyRecoveryResponse.State.FOUND,actionId,digest,command.result())
                :new GovernedPolicyRecoveryResponse(GovernedPolicyRecoveryResponse.State.INTENT_CONFLICT,actionId,digest,null);
        }));
    });}
    private Mono<Optional<GovernedPolicyCommandResponse>> retained(PolicyBindingAdmission.Permit permit,UUID actionId,String digest){
        return operations.findByTenantIdAndOwnerIssuerAndOwnerSubjectAndActionId(permit.resourceTenantId(),permit.actor().issuer(),permit.actor().subject(),actionId)
            .flatMap(operation->{
                if(!digest.equals(operation.intentDigest()))return Mono.just(Optional.of(new GovernedPolicyCommandResponse(GovernedPolicyCommandResponse.Status.REFUSED,actionId,digest,null)));
                return valid(integrity.verifyReceipt(operation.operationId())).then(receipts.findByReceiptIdAndTenantIdAndOwnerIssuerAndOwnerSubject(operation.receiptId(),permit.resourceTenantId(),permit.actor().issuer(),permit.actor().subject()))
                    .switchIfEmpty(Mono.error(refused())).flatMap(receipt->bindings.findByTenantIdAndOwnerIssuerAndOwnerSubjectAndPolicyId(permit.resourceTenantId(),permit.actor().issuer(),permit.actor().subject(),receipt.policyId())
                    .filter(binding->binding.partyId().equals(permit.partyId())).switchIfEmpty(Mono.error(refused())).map(binding->{
                        var result=decode(receipt.resultJson());
                        if(!receipt.operationId().equals(operation.operationId()) || !receipt.actionId().equals(actionId) || !digest.equals(receipt.intentDigest())
                            || !receipt.eventId().equals(operation.eventId()) || !receipt.policyId().equals(operation.policyId()) || !result.policyId().equals(operation.policyId())
                            || !receipt.resultDigest().equals(result.bindingReceiptDigest()) || !receipt.resultDigest().equals(receiptDigest(permit,actionId,digest,result.policyId(),result.policyStatus(),result.bindingVersion(),result.acceptanceId(),result.termsDigest(),receipt.eventRecordHash())))throw refused();
                        return Optional.of(committed(actionId,digest,result));
                    }));
            }).defaultIfEmpty(Optional.empty());
    }
    private Mono<Void> retain(PolicyBindingAdmission.Permit permit,UUID actionId,String digest,UUID operationId,UUID receiptId,GovernedPolicyBindingResult result,PolicyBindingAuditRootImpl.Effect effect){
        var record=effect.record();var decisions=effect.decisions();
        var operation=new PolicyBindingOperation(operationId,permit.resourceTenantId(),permit.actor().issuer(),permit.actor().subject(),permit.actor().clientId(),permit.actor().platformTenantId(),permit.processId(),permit.correlationId(),actionId,permit.request().action().name(),digest,result.policyId(),receiptId,record.event().eventId(),record.event().evidenceDigest(),permit.bindingId(),permit.bindingVersion(),permit.bindingDigest(),decisions.authorization().policyRevision(),decisions.authorization().decisionId(),decisions.admission().policyRevision(),decisions.admission().decisionId(),decisions.digest());
        var receipt=new PolicyBindingReceipt(receiptId,permit.resourceTenantId(),permit.actor().issuer(),permit.actor().subject(),operationId,actionId,digest,result.policyId(),encode(result),result.bindingReceiptDigest(),record.event().eventId(),record.recordHash());
        return insert(operation).then(insert(receipt)).then(valid(integrity.verifyReceipt(operationId)))
            .then(receipts.findByReceiptIdAndTenantIdAndOwnerIssuerAndOwnerSubject(receiptId,permit.resourceTenantId(),permit.actor().issuer(),permit.actor().subject())
                .filter(receipt::equals).switchIfEmpty(Mono.error(refused())).then());
    }
    private Mono<Void> insert(Object row){var strategy=template.getDataAccessStrategy();var mapper=strategy.getStatementMapper();
        StatementMapper.InsertSpec insert=mapper.createInsert(strategy.getTableName(row.getClass()));var outbound=strategy.getOutboundRow(row);
        for(var column:outbound.keySet())insert=insert.withColumn(column,outbound.get(column));
        return one(template.getDatabaseClient().sql(mapper.getMappedObject(insert)).fetch().rowsUpdated());
    }
    private Mono<Void> history(UUID policyId,PolicyStatus status,LocalDateTime now){return insert(PolicyStatusHistory.builder().policyStatusHistoryId(id()).policyId(policyId).policyStatus(status).statusReason("Governed sandbox policy transition").changedAt(now).createdAt(now).updatedAt(now).build());}
    private Mono<Void> protocol(){return valid(integrity.verifyProtocol());}
    private static Mono<Void> valid(Mono<Boolean> source){return source.filter(Boolean.TRUE::equals).switchIfEmpty(Mono.error(refused())).then();}
    private static Mono<Void> one(Mono<Long> source){return source.filter(value->value==1L).switchIfEmpty(Mono.error(refused())).then();}
    private static void require(PolicyBindingAdmission.Permit permit,PolicyBindingAdmission.Action action,UUID actionId,String digest,UUID policyId){if(permit.request().action()!=action || !permit.request().actionId().equals(actionId) || !permit.request().intentDigest().equals(digest) || !Objects.equals(permit.request().policyId(),policyId))throw refused();}
    private UUID id(){return PolicyBindingValues.id(ids.get());}
    private String encode(Object value){try{String encoded=json.writeValueAsString(value);if(encoded.getBytes(java.nio.charset.StandardCharsets.UTF_8).length>65536)throw refused();return encoded;}catch(com.fasterxml.jackson.core.JsonProcessingException e){throw refused();}}
    private GovernedPolicyBindingResult decode(String value){try{if(value==null || value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length>65536)throw refused();return json.readValue(value,GovernedPolicyBindingResult.class);}catch(com.fasterxml.jackson.core.JsonProcessingException e){throw refused();}}
    private static BigDecimal amount(AcceptedQuoteEvidence quote,String key){try{var value=new BigDecimal(Objects.requireNonNull(quote.coverageTerms().get(key)));if(value.signum()<0 || value.precision()>19 || value.scale()>4)throw refused();return value;}catch(NumberFormatException|NullPointerException e){throw refused();}}
    private static String receiptDigest(PolicyBindingAdmission.Permit permit,UUID actionId,String digest,UUID policyId,PolicyStatus status,long version,UUID acceptanceId,String termsDigest,String recordHash){return PolicyBindingValues.hash("CORE_POLICY_RECEIPT_V1",permit.resourceTenantId().toString(),permit.actor().issuer(),permit.actor().subject(),actionId.toString(),digest,policyId.toString(),status.name(),Long.toString(version),acceptanceId.toString(),termsDigest,recordHash);}
    private static GovernedPolicyCommandResponse committed(UUID actionId,String digest,GovernedPolicyBindingResult result){return new GovernedPolicyCommandResponse(GovernedPolicyCommandResponse.Status.COMMITTED,actionId,digest,result);}
    private static PolicyBindingRefusedException refused(){return new PolicyBindingRefusedException();}
}
