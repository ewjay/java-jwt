package com.auth0.msg;

import java.util.List;
import java.util.Map;

public class JsonResponseDescriptor extends AbstractMessage{

    public JsonResponseDescriptor() {
    }

    public JsonResponseDescriptor(Map<String, Object> claims) {
        super(claims);
    }

    @Override
    protected List<String> getRequiredClaims() {
        return null;
    }

    @Override
    public Map<String, Object> getClaims() throws InvalidClaimsException {
        return super.getClaims();
    }

    @Override
    public MessageType getMessageType() {
        return MessageType.JSON_RESPONSE_DESCRIPTOR;
    }

    @Override
    public boolean hasError() {
        return false;
    }
}
