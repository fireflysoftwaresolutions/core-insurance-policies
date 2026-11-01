package io.fireflysoftware.core.insurance.policies.core.services.binding.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.fireflysoftware.core.contract.sdk.api.ContractPartiesApi;
import io.fireflysoftware.core.contract.sdk.api.ContractsApi;
import io.fireflysoftware.core.contract.sdk.invoker.ApiClient;
import io.fireflysoftware.core.contract.sdk.model.ContractPartyDTO;
import io.fireflysoftware.core.contract.sdk.model.PaginationResponseContractPartyDTO;
import io.fireflysoftware.core.insurance.policies.core.services.binding.*;
import io.fireflysoftware.core.insurance.policies.interfaces.binding.GovernedPolicyBindRequest;
import java.math.BigDecimal;
import java.net.URI;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.UnaryOperator;
import org.fireflyframework.kernel.audit.AuditActor;
import org.junit.jupiter.api.Test;
import org.springframework.http.*;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ClientHttpResponse;
import org.springframework.mock.http.client.reactive.MockClientHttpRequest;
import org.springframework.mock.http.client.reactive.MockClientHttpResponse;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import static org.junit.jupiter.api.Assertions.*;

/** Actual generated transport/decoder controls; trusted SPI inputs do not establish provider or database acceptance. */
class GeneratedSdkPolicyContractPortTest {
    static final Instant NOW=Instant.parse("2026-10-31T12:00:00Z");
    static final Clock CLOCK=Clock.fixed(NOW,ZoneOffset.UTC);
    static final UUID TENANT=id(1),PARTY=id(2),PRODUCT=id(3),CONTRACT=id(4),ROLE=id(5),MEMBERSHIP=id(6),BINDING=id(7);
    static final String DIGEST="a".repeat(64),TOKEN="synthetic-contract-caller";
    static UUID id(int value){return UUID.fromString("10000000-0000-4000-8000-%012d".formatted(value));}
    static GovernedPolicyBindRequest request(){return new GovernedPolicyBindRequest(id(8),id(9),PARTY,PRODUCT,id(10),1,1,id(11),DIGEST,DIGEST,CONTRACT,"SANDBOX-1",LocalDate.of(2027,1,1),LocalDate.of(2028,1,1));}
    static PolicyBindingAdmission.Permit permit(GovernedPolicyBindRequest request){return new PolicyBindingAdmission.Permit(PolicyBindingAdmission.Request.bind(request),TENANT,PARTY,BINDING,1,DIGEST,new AuditActor("https://issuer.invalid","opaque subject","policy-client",TENANT.toString(),null,null),"policy-v1",id(12),id(13),NOW,System.nanoTime(),NOW.plusSeconds(5));}
    static AcceptedQuoteEvidence quote(){return new AcceptedQuoteEvidence(TENANT,id(9),PARTY,PRODUCT,id(10),1,1,id(11),id(14),DIGEST,DIGEST,"USD",new BigDecimal("100.00"),BigDecimal.ZERO,BigDecimal.ZERO,Map.of("coverageCode","SANDBOX_PROPERTY_DAMAGE","coverageStart","2027-01-01","coverageEnd","2028-01-01"),id(15),DIGEST,DIGEST,"firefly-sandbox-property-1","illustrative-property-1",NOW,"https://issuer.invalid","opaque subject");}
    static String contract(){return """
        {"contractId":"%s","productId":"%s","currencyCode":"USD","contractStatus":"ACTIVE",
         "startDate":"2026-01-01T00:00:00","endDate":"2030-01-01T00:00:00"}
        """.formatted(CONTRACT,PRODUCT);}
    static String page(){return """
        {"content":[{"contractPartyId":"%s","contractId":"%s","partyId":"%s","roleInContractId":"%s",
         "isActive":true,"dateJoined":"2026-01-01T00:00:00"}],"totalElements":1,"totalPages":1,"currentPage":0}
        """.formatted(MEMBERSHIP,CONTRACT,PARTY,ROLE);}
    record Captured(String method,String path,List<String> authorization,String retryKey,String body){}
    static final class FixtureImpl {
        final List<Captured> captured=new CopyOnWriteArrayList<>();
        final PolicyContractClientProvider.Clients clients;
        FixtureImpl(String contract,String page,HttpStatus status){
            ClientHttpConnector connector=(method,uri,callback)->{
                var outgoing=new MockClientHttpRequest(method,uri);
                return callback.apply(outgoing).then(Mono.defer(outgoing::getBodyAsString)).map(body->{
                    captured.add(new Captured(method.name(),uri.getPath(),List.copyOf(outgoing.getHeaders().getOrEmpty(HttpHeaders.AUTHORIZATION)),outgoing.getHeaders().getFirst("X-Idempotency-Key"),body));
                    var response=new MockClientHttpResponse(status);response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
                    response.setBody(uri.getPath().endsWith("/parties/filter")?page:contract);
                    return (ClientHttpResponse)response;
                });
            };
            var api=new ApiClient(ApiClient.buildWebClientBuilder().clientConnector(connector).build()).setBasePath("https://contract.invalid");
            api.setBearerToken(TOKEN);
            var binding=new PolicyContractClientProvider.ServerBinding(TENANT,BINDING,1,DIGEST,URI.create("https://contract.invalid"),ROLE,NOW.plusSeconds(60));
            clients=new PolicyContractClientProvider.Clients(binding,new ContractsApi(api),new ContractPartiesApi(api));
        }
        Mono<Void> invoke(){var request=request();return new GeneratedSdkPolicyContractPortImpl(original->Mono.just(clients),CLOCK).requireExisting(permit(request),request,quote());}
    }

    @Test void actualGeneratedBearerAndTypedPartyPageAdmitTheExactActiveContract() throws Exception {
        Path expected=Path.of("..","..","core-common-contract-mgmt","core-common-contract-mgmt-sdk","target","classes").toRealPath();
        for(Class<?> type:List.of(ApiClient.class,ContractPartyDTO.class,PaginationResponseContractPartyDTO.class))
            FreshSourceSdkFixture.require(type,expected);
        var fixture=new FixtureImpl(contract(),page(),HttpStatus.OK);
        StepVerifier.create(fixture.invoke()).verifyComplete();
        assertEquals(2,fixture.captured.size());
        for(var captured:fixture.captured){assertEquals(List.of("Bearer "+TOKEN),captured.authorization());assertNull(captured.retryKey());}
        var get=fixture.captured.stream().filter(x->x.method().equals("GET")).findFirst().orElseThrow();
        assertEquals("/api/v1/contracts/"+CONTRACT,get.path());
        var post=fixture.captured.stream().filter(x->x.method().equals("POST")).findFirst().orElseThrow();
        assertEquals("/api/v1/contracts/"+CONTRACT+"/parties/filter",post.path());
        JsonNode body=new ObjectMapper().readTree(post.body());
        assertEquals(CONTRACT.toString(),body.at("/filters/contractId").asText());assertEquals(PARTY.toString(),body.at("/filters/partyId").asText());
        assertEquals(ROLE.toString(),body.at("/filters/roleInContractId").asText());assertTrue(body.at("/filters/isActive").asBoolean());
        assertEquals(2,body.at("/pagination/pageSize").asInt());
    }

    @Test void absentOrInactiveTypedPartyCannotBecomeAValidRelationship(){
        for(String body:List.of(page().replace("\"isActive\":true","\"isActive\":false"),page().replace("\"isActive\":true","\"isActive\":null"),page().replace("\"isActive\":true,",""),"{\"content\":[null],\"totalElements\":1,\"totalPages\":1,\"currentPage\":0}"))
            StepVerifier.create(new FixtureImpl(contract(),body,HttpStatus.OK).invoke()).expectError(PolicyBindingRefusedException.class).verify();
    }

    @Test void foreignPartyRoleAndInvalidCoverageDatesRemainRefused(){
        for(UnaryOperator<String> change:List.<UnaryOperator<String>>of(value->value.replace(PARTY.toString(),id(20).toString()),value->value.replace(ROLE.toString(),id(21).toString()),value->value.replace("2026-01-01T00:00:00","2027-01-02T00:00:00"),value->value.replace("\"dateJoined\":\"2026-01-01T00:00:00\"","\"dateJoined\":\"2026-01-01T00:00:00\",\"dateLeft\":\"2027-12-31T00:00:00\"")))
            StepVerifier.create(new FixtureImpl(contract(),change.apply(page()),HttpStatus.OK).invoke()).expectError(PolicyBindingRefusedException.class).verify();
    }

    @Test void productCurrencyAndIncompletePaginationRemainRefused(){
        for(String contract:List.of(contract().replace(PRODUCT.toString(),id(22).toString()),contract().replace("USD","EUR"),contract().replace("ACTIVE","DRAFT"),contract().replace("2030-01-01T00:00:00","2027-12-31T00:00:00")))
            StepVerifier.create(new FixtureImpl(contract,page(),HttpStatus.OK).invoke()).expectError(PolicyBindingRefusedException.class).verify();
        for(String page:List.of(page().replace("\"totalElements\":1","\"totalElements\":2"),page().replace("\"totalPages\":1","\"totalPages\":2"),page().replace("\"currentPage\":0","\"currentPage\":1")))
            StepVerifier.create(new FixtureImpl(contract(),page,HttpStatus.OK).invoke()).expectError(PolicyBindingRefusedException.class).verify();
    }

    @Test void protectedReceiverRefusalIsPreservedAsForbidden(){
        for(HttpStatus status:List.of(HttpStatus.UNAUTHORIZED,HttpStatus.FORBIDDEN))
            StepVerifier.create(new FixtureImpl("{}","{}",status).invoke()).expectErrorSatisfies(error->{var response=assertInstanceOf(ResponseStatusException.class,error);assertEquals(HttpStatus.FORBIDDEN,response.getStatusCode());}).verify();
    }

    @Test void missingOrMismatchedServerBindingRefusesBeforeAnyGeneratedRequest(){
        var fixture=new FixtureImpl(contract(),page(),HttpStatus.OK);var request=request();
        StepVerifier.create(new GeneratedSdkPolicyContractPortImpl(original->Mono.empty(),CLOCK).requireExisting(permit(request),request,quote())).expectError(GovernedPolicyUnavailableException.class).verify();
        var wrong=new PolicyContractClientProvider.ServerBinding(id(23),BINDING,1,DIGEST,URI.create("https://contract.invalid"),ROLE,NOW.plusSeconds(60));
        var clients=new PolicyContractClientProvider.Clients(wrong,fixture.clients.contracts(),fixture.clients.parties());
        StepVerifier.create(new GeneratedSdkPolicyContractPortImpl(original->Mono.just(clients),CLOCK).requireExisting(permit(request),request,quote())).expectError(PolicyBindingRefusedException.class).verify();
        assertTrue(fixture.captured.isEmpty());
    }
}
