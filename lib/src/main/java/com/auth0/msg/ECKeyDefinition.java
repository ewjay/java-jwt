package com.auth0.msg;

public class ECKeyDefinition extends KeyDefinition {
    private String crv;

    /**
     * Instantiate a ECKeyDefinition
     *
     * @param KeyType the type of the key either EC or RSA
     * @param KeyUseCase will the key be used for signature or encryption
     * @return String crv the curve used for EC keys
     */
    public ECKeyDefinition(KeyType type, KeyUseCase useCase, String crv) {
        this.type = type;
        this.useCase.add(useCase);
        this.crv = crv;
    }

    public String getCrv() {
        return crv;
    }

    public void setCrv(String crv) {
        this.crv = crv;
    }
}