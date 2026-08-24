package me.rainma22.dillydally.validation.states;

import java.security.KeyPair;
import java.time.LocalDateTime;
import java.util.ArrayDeque;
import java.util.ArrayList;

import me.rainma22.dillydally.conf.ConfBean;
import me.rainma22.dillydally.validation.NewOrderResponse;
import me.rainma22.dillydally.validation.ResourceLocationResponse;
import me.rainma22.dillydally.validation.ValidationHttpClient;

public class OrderCreatedState implements ValidatorState {

    private KeyPair kp;
    private ResourceLocationResponse resourceLocations;
    private ValidationHttpClient client;
    private String accountLocation;
    private String orderLocation;
    private LocalDateTime orderExpiry;
    private NewOrderResponse orderResponse;
    private ConfBean conf;

    public OrderCreatedState(KeyPair kp, ResourceLocationResponse resourceLocations,
            ValidationHttpClient client, String accountLocation, String orderLocation,
            LocalDateTime orderExpiry, NewOrderResponse orderResponse, ConfBean conf) {
        this.kp = kp;
        this.resourceLocations = resourceLocations;
        this.client = client;
        this.accountLocation = accountLocation;
        this.orderLocation = orderLocation;
        this.orderResponse = orderResponse;
        this.orderExpiry = orderExpiry;
        this.conf = conf;
    }

    @Override
    public boolean isFinal() {
        return false;
    }

    @Override
    public ValidatorState nextState() {
        if (orderExpiry.isBefore(LocalDateTime.now())) {
            // retry by regressing back to new Order
            return new AccountCreatedState(kp, resourceLocations, client, accountLocation, conf);
        }
        try {
            var authorizations = orderResponse.getAuthorizations();

            return new CompletingAuthorizationState(kp, resourceLocations, client,
                    accountLocation, orderLocation,
                    orderExpiry, orderResponse, new ArrayDeque<>(authorizations), new ArrayList<String>(), conf);
        } catch (Exception e) {
            return new FailedState(e);
        }
    }

}
