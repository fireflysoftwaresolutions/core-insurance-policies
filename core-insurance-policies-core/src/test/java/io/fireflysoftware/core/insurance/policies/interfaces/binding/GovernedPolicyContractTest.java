package io.fireflysoftware.core.insurance.policies.interfaces.binding;

import java.time.LocalDate;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class GovernedPolicyContractTest {
    private static final String DIGEST="a".repeat(64);
    private GovernedPolicyBindRequest request(UUID action) {
        return new GovernedPolicyBindRequest(action,UUID.fromString("10000000-0000-4000-8000-000000000001"),
                UUID.fromString("10000000-0000-4000-8000-000000000002"),UUID.fromString("10000000-0000-4000-8000-000000000003"),
                UUID.fromString("10000000-0000-4000-8000-000000000004"),1,1,
                UUID.fromString("10000000-0000-4000-8000-000000000005"),DIGEST,DIGEST,
                UUID.fromString("10000000-0000-4000-8000-000000000006"),"PROPERTY-1",LocalDate.of(2027,1,1),LocalDate.of(2028,1,1));
    }
    @Test void unchangedActionAndIntentHaveStableCanonicalDigest(){var id=UUID.randomUUID();assertEquals(request(id).intentDigest(),request(id).intentDigest());}
    @Test void replacingActionChangesIntentIdentity(){assertNotEquals(request(UUID.randomUUID()).intentDigest(),request(UUID.randomUUID()).intentDigest());}
    @Test void bindingRequiresAnExistingContract(){var r=request(UUID.randomUUID());assertThrows(NullPointerException.class,()->new GovernedPolicyBindRequest(r.actionId(),r.submissionId(),r.partyId(),r.productId(),r.offerId(),1,1,r.acceptanceActionId(),DIGEST,DIGEST,null,r.policyNumber(),r.inceptionDate(),r.expiryDate()));}
    @Test void uncertainCommandCannotCarryAResult(){var r=request(UUID.randomUUID());assertThrows(IllegalArgumentException.class,()->new GovernedPolicyCommandResponse(GovernedPolicyCommandResponse.Status.COMMITTED,r.actionId(),r.intentDigest(),null));}
    @Test void missingRecoveryIsAnObservationNotARefusalOrSuccess(){var r=request(UUID.randomUUID());var x=new GovernedPolicyRecoveryResponse(GovernedPolicyRecoveryResponse.State.NOT_OBSERVED_AT_THIS_READ,r.actionId(),r.intentDigest(),null);assertNull(x.result());}
    @Test void malformedUnicodeCannotHashAsAReplacementCharacter(){assertThrows(IllegalArgumentException.class,()->PolicyBindingValues.text("bad\ud800",64));}
    @Test void issueMustBindAnExistingReceiptAndGeneration(){assertThrows(IllegalArgumentException.class,()->new GovernedPolicyIssueRequest(UUID.randomUUID(),0,DIGEST));}
}
