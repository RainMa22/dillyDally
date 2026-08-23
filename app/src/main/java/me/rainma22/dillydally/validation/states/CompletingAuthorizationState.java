package me.rainma22.dillydally.validation.states;

import java.security.KeyPair;
import java.time.LocalDateTime;
import java.util.List;

import me.rainma22.dillydally.conf.ConfBean;
import me.rainma22.dillydally.validation.NewOrderResponse;
import me.rainma22.dillydally.validation.ResourceLocationResponse;
import me.rainma22.dillydally.validation.ValidationHttpClient;

public class CompletingAuthorizationState implements ValidatorState {

    private KeyPair kp;
    private ResourceLocationResponse resourceLocations;
    private ValidationHttpClient client;
    private String accountLocation;
    private String orderLocation;
    private LocalDateTime orderExpiry;
    private NewOrderResponse orderResponse;
    private List<String> authorizationToDo;
    private List<String> completed;
    private ConfBean conf;

    public CompletingAuthorizationState(KeyPair kp, ResourceLocationResponse resourceLocations,
            ValidationHttpClient client, String accountLocation, String orderLocation, LocalDateTime orderExpiry,
            NewOrderResponse orderResponse, List<String> authorizationToDo, List<String> completed, ConfBean conf) {
        this.kp = kp;
        this.resourceLocations = resourceLocations;
        this.client = client;
        this.accountLocation = accountLocation;
        this.orderLocation = orderLocation;
        this.orderExpiry = orderExpiry;
        this.orderResponse = orderResponse;
        this.authorizationToDo = authorizationToDo;
        this.completed = completed;
        this.conf = conf;
    }

    @Override
    public boolean isFinal() {
        return false;
    }

    @Override
    public ValidatorState nextState() {
        if (orderExpiry.isBefore(LocalDateTime.now())) {
            // if expired: retry by regressing back to new Order
            return new AccountCreatedState(kp, resourceLocations, client, accountLocation, conf);
        }
        try {
            throw new UnsupportedOperationException("Not implemented yet");
        } catch (Exception e) {
            return new FailedState(e);
        }
    }

}
