package io.fireflysoftware.core.insurance.policies.web.openapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.*;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;
import static org.junit.jupiter.api.Assertions.*;

@ActiveProfiles("openapi-gen")
@SpringBootTest(classes=OpenApiGenApplication.class,webEnvironment=SpringBootTest.WebEnvironment.MOCK,properties={"spring.main.web-application-type=reactive","springdoc.api-docs.enabled=true","springdoc.api-docs.version=OPENAPI_3_0"})
class GovernedPolicyProducerContractTest {
    @Autowired ApplicationContext context;
    JsonNode document(String name)throws Exception{byte[] bytes=WebTestClient.bindToApplicationContext(context).configureClient().responseTimeout(Duration.ofSeconds(3)).build().get().uri("/v3/api-docs").exchange().expectStatus().isOk().expectBody().returnResult().getResponseBody();assertNotNull(bytes);assertTrue(bytes.length<=4*1024*1024);Path path=Path.of("target",name+"-governed-policy-openapi.json");Files.createDirectories(path.getParent());Files.write(path,bytes);byte[] yaml=WebTestClient.bindToApplicationContext(context).configureClient().responseTimeout(Duration.ofSeconds(3)).build().get().uri("/v3/api-docs.yaml").exchange().expectStatus().isOk().expectBody().returnResult().getResponseBody();assertNotNull(yaml);assertTrue(yaml.length<=4*1024*1024);Files.write(Path.of("target",name+"-governed-policy-openapi.yml"),yaml);var document=new ObjectMapper().readTree(bytes);assertEquals(document,new ObjectMapper(new com.fasterxml.jackson.dataformat.yaml.YAMLFactory()).readTree(yaml));var previous=new ObjectMapper(new com.fasterxml.jackson.dataformat.yaml.YAMLFactory()).readTree(Files.readAllBytes(Path.of("..","core-insurance-policies-sdk","src","main","resources","openapi.yml")));int retained=0;for(var paths=previous.path("paths").fields();paths.hasNext();){var pathEntry=paths.next();for(var methods=pathEntry.getValue().fields();methods.hasNext();){var method=methods.next();if(!java.util.Set.of("get","post","put","patch","delete","head","options","trace").contains(method.getKey()))continue;assertEquals(method.getValue().path("operationId"),document.path("paths").path(pathEntry.getKey()).path(method.getKey()).path("operationId"));retained++;}}assertTrue(retained>=60);return document;}
    @Test void originalProducerDeclaresTypedJsonAndBearerForAllGovernedOperations()throws Exception{var doc=document("typed");for(var expected:List.of(new String[]{"/api/v1/policies/governed/bindings","post","bindGovernedPolicy","GovernedPolicyCommandResponse"},new String[]{"/api/v1/policies/governed/recovery/{actionId}","get","recoverGovernedPolicyBinding","GovernedPolicyRecoveryResponse"},new String[]{"/api/v1/policies/{policyId}/governed/issue","post","issueGovernedPolicy","GovernedPolicyCommandResponse"})){var op=doc.path("paths").path(expected[0]).path(expected[1]);assertEquals(expected[2],op.path("operationId").asText());assertEquals("#/components/schemas/"+expected[3],op.path("responses").path("200").path("content").path("application/json").path("schema").path("$ref").asText());assertTrue(op.path("security").toString().contains("bearerAuth"));assertTrue(op.path("tags").toString().contains("GovernedPolicies"));}}
    @Test void originalProducerRequiresIdentityAndAllFourOutcomeStates()throws Exception{var doc=document("outcome");var schema=doc.path("components").path("schemas").path("GovernedPolicyCommandResponse");var required=new java.util.HashSet<String>();schema.path("required").forEach(v->required.add(v.asText()));assertTrue(required.containsAll(List.of("status","actionId","intentDigest")));var status=schema.path("properties").path("status");if(status.has("$ref"))status=doc.at(status.path("$ref").asText().substring(1));var actual=new java.util.HashSet<String>();status.path("enum").forEach(v->actual.add(v.asText()));assertEquals(java.util.Set.of("COMMITTED","COMMITTED_RESPONSE_UNAVAILABLE","OUTCOME_UNKNOWN","REFUSED"),actual);}
    @Test void producerHasNoBusinessConnectionFactory()throws Exception{document("no-business");assertEquals(0,context.getBeanNamesForType(io.r2dbc.spi.ConnectionFactory.class,false,false).length);}
}
