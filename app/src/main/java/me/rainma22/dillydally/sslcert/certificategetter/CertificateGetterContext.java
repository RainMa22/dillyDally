package me.rainma22.dillydally.sslcert.certificategetter;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import me.rainma22.dillydally.conf.ConfBean;
import me.rainma22.dillydally.sslcert.ACMEHttpClient;
import me.rainma22.dillydally.sslcert.NewOrderResponse;
import me.rainma22.dillydally.sslcert.ResourceLocationResponse;
import me.rainma22.dillydally.sslcert.certificategetter.states.ARIAccountCreatedState;
import me.rainma22.dillydally.sslcert.certificategetter.states.AccountCreatedState;
import me.rainma22.dillydally.sslcert.certificategetter.states.AuthorizationValidationState;
import me.rainma22.dillydally.sslcert.certificategetter.states.CertificateGetterState;
import me.rainma22.dillydally.sslcert.certificategetter.states.CheckRenewalState;
import me.rainma22.dillydally.sslcert.certificategetter.states.CompletingAuthorizationState;
import me.rainma22.dillydally.sslcert.certificategetter.states.RequestCertificateState;
import me.rainma22.dillydally.sslcert.certificategetter.states.GetResourceLocationState;
import me.rainma22.dillydally.sslcert.certificategetter.states.InitializedState;
import me.rainma22.dillydally.sslcert.certificategetter.states.OrderCreatedState;
import me.rainma22.dillydally.sslcert.certificategetter.states.OrderValidationState;
import me.rainma22.dillydally.sslcert.certificategetter.states.PollForCertificateState;

public class CertificateGetterContext {
    private final KeyPair acmeKeyPair;
    private ResourceLocationResponse resourceLocations = null;
    private ACMEHttpClient client;
    private String accountLocation = null;
    private String replaces = null;
    private final ConfBean conf;

    private KeyPair sslKeyPair = null;
    private X509Certificate[] certChain = null;

    String orderLocation = null;
    private NewOrderResponse orderResponse = null;
    private LocalDateTime orderExpiry = null;
    private boolean orderValidated = false;

    private Deque<String> authorizationToDo = null;
    private final List<CompletableFuture<?>> completedChallenges = new ArrayList<>();

    private int numRetries = 0;
    private Exception error = new IOException("Not completed yet.");

    public CertificateGetterContext(KeyPair acmeKeyPair, ConfBean conf) {
        this.acmeKeyPair = acmeKeyPair;
        this.conf = conf;
    }

    public CertificateGetterState getState() {
        if (resourceLocations == null)
            return new GetResourceLocationState();
        if (accountLocation == null)
            return new InitializedState();
        if (orderExpiry == null || orderExpiry.isBefore(LocalDateTime.now())) {
            orderValidated = false;
            authorizationToDo = null;
            completedChallenges.clear();
            if (!resourceLocations.isARISupported() || replaces == null) {
                return new AccountCreatedState();
            } else {
                return new ARIAccountCreatedState();
            }
        }
        if (authorizationToDo == null)
            return new OrderCreatedState();
        if (!authorizationToDo.isEmpty())
            return new CompletingAuthorizationState();
        if (authorizationToDo.isEmpty() && !completedChallenges.isEmpty())
            return new AuthorizationValidationState();
        if (!orderValidated)
            return new OrderValidationState();
        if (orderValidated && sslKeyPair == null) 
            return new RequestCertificateState();
        if(certChain == null)
            return new PollForCertificateState();
        return new CheckRenewalState();
    }

    public KeyPair getAcmeKeyPair() {
        return acmeKeyPair;
    }

    public ResourceLocationResponse getResourceLocations() {
        return resourceLocations;
    }

    public void setResourceLocations(ResourceLocationResponse resourceLocations) {
        this.resourceLocations = resourceLocations;
        this.client = new ACMEHttpClient(resourceLocations);
    }

    public String getAccountLocation() {
        return accountLocation;
    }

    public void setAccountLocation(String accountLocation) {
        this.accountLocation = accountLocation;
    }

    public String getReplaces() {
        return replaces;
    }

    public void setReplaces(String replaces) {
        this.replaces = replaces;
    }

    public ConfBean getConf() {
        return conf;
    }

    public KeyPair getSslKeyPair() {
        return sslKeyPair;
    }

    public void setSslKeyPair(KeyPair sslKeyPair) {
        this.sslKeyPair = sslKeyPair;
    }

    public X509Certificate[] getCertChain() {
        return certChain;
    }

    public void setCertChain(X509Certificate[] certChain) {
        this.certChain = certChain;
    }

    public String getOrderLocation() {
        return orderLocation;
    }

    public void setOrderLocation(String orderLocation) {
        this.orderLocation = orderLocation;
    }

    public NewOrderResponse getOrderResponse() {
        return orderResponse;
    }

    public void setOrderResponse(NewOrderResponse newOrderResponse) {
        this.orderResponse = newOrderResponse;
    }

    public boolean isOrderValidated() {
        return orderValidated;
    }

    public void setOrderValidated(boolean orderValidated) {
        this.orderValidated = orderValidated;
    }

    public LocalDateTime getOrderExpiry() {
        return orderExpiry;
    }

    public void setOrderExpiry(LocalDateTime orderExpiry) {
        this.orderExpiry = orderExpiry;
    }

    public Deque<String> getAuthorizationToDo() {
        return authorizationToDo;
    }

    public void setAuthorizationToDo(Deque<String> authorizationToDo) {
        this.authorizationToDo = authorizationToDo;
    }

    public List<CompletableFuture<?>> getCompletedChallenges() {
        return completedChallenges;
    }

    public Exception getError() {
        return error;
    }

    public void updateError(Exception error) {
        this.error = error;
        this.numRetries++;
    }

    public ACMEHttpClient getClient() {
        return client;
    }

    public int getNumRetries() {
        return numRetries;
    }

}
