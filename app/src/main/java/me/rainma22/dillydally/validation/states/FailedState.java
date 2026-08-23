package me.rainma22.dillydally.validation.states;

public class FailedState implements ValidatorState {

    private Exception error;

    public FailedState(Exception error) {
        this.error = error;
    }

    @Override
    public boolean isFinal() {
        return true;
    }

    @Override
    public ValidatorState nextState() {
        return new FailedState(new UnsupportedOperationException("Attempted to get nextState on a Failed State", 
        error));
    }

    public Exception getError() {
        return error;
    }

}
