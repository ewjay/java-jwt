package com.auth0.msg;

import java.util.List;
import java.util.Map;

public class WebfingerRequestMessage extends AbstractMessage {
    public WebfingerRequestMessage() {
    }

    public WebfingerRequestMessage(Map<String, Object> claims){
        super(claims);
    }

    @Override
    protected List<String> getRequiredClaims() {
        return null;
    }

    @Override
    public Map<String, Object> getClaims() throws InvalidClaimException {
        return super.getClaims();
    }

    @Override
    public MessageType fetchMessageType() {
        return MessageType.WEBFINGER_REQUEST_MESSAGE;
    }

    @Override
    public boolean hasError() {
        return false;
    }

    @Override
    public boolean allowCustomClaims() {
        return false;
    }
}
