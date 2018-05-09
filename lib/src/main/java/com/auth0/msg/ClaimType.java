package com.auth0.msg;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * This enum specifies the claims and their allowed values to enable validation of messages
 */
public enum ClaimType {
    BOOLEAN("Boolean", Boolean.class),
    STRING("String", String.class),
    INT("Int", Integer.class),
    LIST("List", List.class),
    ARRAY("Array", Array.class),
    DATE("Date", Date.class),
    LONG("Long", Long.class),
    ID_TOKEN("ID_Token", IDToken.class);
    // TODO There are potentially other claim types that have not been included

    private final String type;
    private final Class classType;
    ClaimType(String type, Class classType) {
        this.type = type;
        this.classType = classType;
    }
}