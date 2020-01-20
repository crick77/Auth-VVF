/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package it.dipvvf.abr.app.corsivvf.ws;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Usato per simulare utenti e gruppi in assenza di ActiveDirectory
 * 
 * @author ospite
 */
public final class UserDatabase {
    private final static UserDatabase _instance = new UserDatabase();
    private final Map<String, String> users;
    private final Map<String, List<String>> groups;
    
    private UserDatabase() {
        users = new HashMap<>();
        groups = new HashMap<>();
        
        users.put("admin", "admin");
        users.put("user1", "pass1");
        users.put("user2", "pass2");
        
        groups.put("admin", Arrays.asList(new String[] {"GAdmin", "GCorsiVVF"}));
        groups.put("user1", Arrays.asList(new String[] {"GCorsiVVF", "GOtherApp"}));
        groups.put("user1", Arrays.asList(new String[] {"GOtherApp"}));
    }
    
    public static UserDatabase connect() {
        return _instance;
    }
    
    public boolean checkUser(String username, String password) {
        String pwd = users.get(username);
        return (pwd!=null) ? pwd.equals(password) : false;
    }
    
    public String[] getUserGroups(String username) {
        List<String> lGrp = groups.get(username);
        return (lGrp!=null) ? lGrp.toArray(new String[0]) : new String[0];
    }
    
    public boolean hasRole(String username, String role) {
        List<String> roles = groups.get(username);
        return (roles!=null) ? roles.contains(role) : false;
    }
}
