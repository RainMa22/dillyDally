package me.rainma22.dillydally.sslcert.states;

public class FailedState implements CertificateGetterState {

    private Exception error;

    public FailedState(Exception error) {
        this.error = error;
    }

    @Override
    public boolean isFinal() {
        return true;
    }

    @Override
    public CertificateGetterState nextState() {
        return new FailedState(new UnsupportedOperationException("Attempted to get nextState on a Failed State", 
        error));
    }

    public Exception getError() {
        return error;
    }

}
