package com.auth0.msg;

import java.util.ArrayList;
import java.util.List;

public class KeyBundle {
    public List<Key> keys = new ArrayList<Key>();
    public void addKey(Key newKey){
        keys.add(newKey);
    }
    public List<Key> getKeys(){
        return keys;
    }
}
