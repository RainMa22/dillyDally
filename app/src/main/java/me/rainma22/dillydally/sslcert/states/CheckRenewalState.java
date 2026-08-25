package me.rainma22.dillydally.sslcert.states;

public class CheckRenewalState implements CertificateGetterState{

    @Override
    public boolean isFinal() {
        return false;
    }

    @Override
    public CertificateGetterState nextState() {
        /*TODO: 
         - ATTMEPTS to use ARI(RFC 9773) to check whether certificate needs renewing;
            - IF ARI is supported: 
                - CHECK using ARI 
                    - IF no renew needed, return CompletedState
                    - ELSE return next ARI RENEWAL State
            - ELSE 
                - CHECK using CERTIFICATE's NOTAFTER timestamp
                - IF current time is some threshold before NOT-AFTER timestamp or current time is after NOT-AFTER timestamp, request a new cert by returning AccountCreatedState
                - ELSE return CompletedState as no renew needed.
         */

        throw new UnsupportedOperationException("Unimplemented method 'nextState'");
    }
    
}
