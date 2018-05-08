package com.auth0.msg;

import java.util.List;

public class Error{
    private List<String> messages;

    public Error(List<String> messages) {
        this.messages = messages;
    }
    public List<String> getMessages() {
        return this.messages;
    }
}