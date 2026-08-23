package me.rainma22.dillydally.validation.states;


public interface ValidatorState {
        boolean isFinal();
        ValidatorState nextState();
}