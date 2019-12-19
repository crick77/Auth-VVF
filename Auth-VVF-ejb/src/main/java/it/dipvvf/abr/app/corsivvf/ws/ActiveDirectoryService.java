/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package it.dipvvf.abr.app.corsivvf.ws;

import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.LocalBean;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebService;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.PartialResultException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.InitialLdapContext;

/**
 *
 * @author riccardo.iovenitti
 */
@Stateless
@LocalBean
@WebService
public class ActiveDirectoryService {
    @Resource(lookup = "adServers")
    String adServers;
    @Resource(lookup = "domainName")
    String domainName;
    @Resource(lookup = "adUser")
    String adUser;
    @Resource(lookup = "adPassword")
    String adPassword;
    String[] serverList;
    Control[] connCtls = new Control[]{new FastBindConnectionControl()};

    @PostConstruct
    private void initialize() {
        if (adServers == null) {
            throw new EJBException("Server di ActiveDirectory non specificati.");
        }
        if (adUser == null || adPassword == null) {
            throw new EJBException("Utente di ActiveDirectory non specificato.");
        }

        serverList = adServers.split(",");
        for(int i = 0;i<serverList.length;i++) {
            serverList[i] = serverList[i].trim();
        }

        if(domainName==null)  {
            // Prova ad estrarre il nome dominio da uno dei server AD indicati
            for (String server : serverList) {
                if (server.split("\\.").length > 1) {
                    domainName = server.substring(server.indexOf(".") + 1);
                    break;
                }
            }

            // Prova con l'ad user se è indicato in forma user@domain
            if (adUser.split("\\@").length > 1) {
                domainName = adUser.substring(adUser.indexOf("@") + 1);
            }
        }

        // niente...prova con l'host attuale
        if (domainName == null) {
            try {
                String fqdn = java.net.InetAddress.getLocalHost().getCanonicalHostName();
                if (fqdn.split("\\.").length > 1) {
                    domainName = fqdn.substring(fqdn.indexOf(".") + 1);
                }
            } catch (java.net.UnknownHostException e) {
            }
        }

        // nessun dominio, errore
        if (domainName == null) {
            throw new EJBException("Impossibile recuperare il dominio locale.");
        }

        // se non disponibile completa l'aduser con il suffisso @domain
        adUser = toFQDNUsername(adUser);
    }

    @WebMethod
    public boolean checkUser(@WebParam(name = "username") String username, @WebParam(name = "password") String password) {
        DirContext ctx = connect(username, password);
        if (ctx != null) {
            try {
                ctx.close();
            } catch (NamingException ne) {
            }

            return true;
        }

        return false;
    }

    @WebMethod
    public String[] getUserGroups(@WebParam(name = "username") String username) {
        DirContext ctx = connect(adUser, adPassword);
        if (ctx != null) {
            try {
                SearchControls controls = new SearchControls();
                controls.setSearchScope(SearchControls.SUBTREE_SCOPE);

                NamingEnumeration<SearchResult> renum = ctx.search(
                    toDC(domainName), 
                    "(& (userPrincipalName=" + toFQDNUsername(username)
                    + ")(objectClass=user))", controls);

                // nessun utente trovato
                if (!renum.hasMore()) {
                    ctx.close();
                    
                    return null;
                }
                SearchResult result = renum.next();

                Attribute memberOf = result.getAttributes().get("memberOf");
                List<String> groups = new LinkedList<>();
                if (memberOf != null) {
                    for (int i = 0; i < memberOf.size(); i++) {
                        Attributes atts = ctx.getAttributes(memberOf.get(i)
                                .toString(), new String[]{"CN"});
                        Attribute att = atts.get("CN");
                        groups.add(att.get().toString());
                    }
                }

                ctx.close();
                return groups.toArray(new String[0]);
            }
            catch(PartialResultException pre) {
                try {
                    ctx.close();
                }
                catch(NamingException ne) { }
                
                return null;
            }
            catch(NamingException ne) { }
        }
        
        throw new EJBException("Errore di accesso all'ActiveDirectory.");
    }
    
    @WebMethod
    public String[] getUserAttribute(@WebParam(name = "username") String username, @WebParam(name = "attribute") String attribute) {
        DirContext ctx = connect(adUser, adPassword);
        if (ctx != null) {
            try {
                SearchControls controls = new SearchControls();
                controls.setSearchScope(SearchControls.SUBTREE_SCOPE);

                NamingEnumeration<SearchResult> renum = ctx.search(
                    toDC(domainName), 
                    "(& (userPrincipalName=" + toFQDNUsername(username)
                    + ")(objectClass=user))", controls);

                // nessun utente trovato
                if (!renum.hasMore()) {
                    ctx.close();
                    
                    return null;
                }
                SearchResult result = renum.next();

                Attribute attValues = result.getAttributes().get(attribute);
                List<String> values = new LinkedList<>();
                if (attValues != null) {
                    for (int i = 0; i < attValues.size(); i++) {
                        values.add(attValues.get(i).toString());
                    }
                }

                ctx.close();
                return values.toArray(new String[0]);
            }
            catch(PartialResultException pre) {
                try {
                    ctx.close();
                }
                catch(NamingException ne) { }
                
                return null;
            }
            catch(NamingException ne) { }
        }
        
        throw new EJBException("Errore di accesso all'ActiveDirectory.");
    }
    
    private DirContext connect(String username, String password) {
        Hashtable<String, String> ldapEnv = new Hashtable<>();
        ldapEnv.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        ldapEnv.put(Context.SECURITY_AUTHENTICATION, "simple");
        ldapEnv.put(Context.SECURITY_PRINCIPAL, toFQDNUsername(username));
        ldapEnv.put(Context.SECURITY_CREDENTIALS, password);

        for (String adServer : serverList) {
            ldapEnv.put(Context.PROVIDER_URL, "ldap://" + adServer + ":389");
            try {
                return new InitialLdapContext(ldapEnv, connCtls);
            } catch (NamingException ne) {
            }
        }

        return null;
    }
    
    private String toFQDNUsername(String username) {
        if (!username.contains("@")) {
            username = username + "@" + domainName;
        }
        return username;
    }

    private String toDC(String domainName) {
        StringBuilder buf = new StringBuilder();
        for (String token : domainName.split("\\.")) {
            if (token.length() == 0) {
                continue; // defensive check
            }
            if (buf.length() > 0) {
                buf.append(",");
            }
            buf.append("DC=").append(token);
        }
        return buf.toString();
    }
    
    class FastBindConnectionControl implements Control {
        @Override
        public String getID() {
            return "1.2.840.113556.1.4.1781";
        }

        @Override
        public boolean isCritical() {
            return true;
        }

        @Override
        public byte[] getEncodedValue() {
            return null;
        }
    }
}
