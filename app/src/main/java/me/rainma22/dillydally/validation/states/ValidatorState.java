package me.rainma22.dillydally.validation.states;

import java.security.KeyPair;

public abstract class ValidatorState {
        protected String accountLocation = null;
        protected String nextNonce = null;
        protected KeyPair kp;
        protected String orderLocation = null;

        abstract ValidatorState nextState();

        public String getAccountLocation() {
                return accountLocation;
        }

        public void setAccountLocation(String accountLocation) {
                this.accountLocation = accountLocation;
        }

        public String getNextNonce() {
                return nextNonce;
        }

        public void setNextNonce(String nextNonce) {
                this.nextNonce = nextNonce;
        }

        public KeyPair getKp() {
                return kp;
        }

        public void setKp(KeyPair kp) {
                this.kp = kp;
        }

        public String getOrderLocation() {
                return orderLocation;
        }

        public void setOrderLocation(String orderLocation) {
                this.orderLocation = orderLocation;
        }
}