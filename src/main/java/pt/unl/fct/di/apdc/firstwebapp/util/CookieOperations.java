package pt.unl.fct.di.apdc.firstwebapp.util;

import javax.ws.rs.core.Cookie;

import com.google.cloud.datastore.*;

public class CookieOperations {
    private final static Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final static KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("Cookie");

    CookieOperations() {
    }

    public static String[] extractCookieParts(String cookieValue) {
        return cookieValue.split("\\.");
    }

    public static void registerCookie(String username, Cookie cookie) {
        Transaction txn = datastore.newTransaction();
        try {
            Key userKey = userKeyFactory.newKey(username);
            Entity cookieEntity = Entity.newBuilder(userKey)
                    .set("cookie", cookie.getValue())
                    .build();
            txn.put(cookieEntity);
            txn.commit();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }

    public static void deleteCookie(String username) {
        Transaction txn = datastore.newTransaction();
        try {
            Key userKey = userKeyFactory.newKey(username);
            Entity user = txn.get(userKey);
            if (user == null) {
                txn.rollback();
                return;
            }
            txn.delete(userKey);
            txn.commit();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }

 public static void updateCookie(String username, Cookie cookie) {
        Transaction txn = datastore.newTransaction();
        try {
            Key userKey = userKeyFactory.newKey(username);
            Entity user = txn.get(userKey);
            if (user == null) {
                txn.rollback();
                return;
            }
            Entity cookieEntity = Entity.newBuilder(userKey)
                    .set("cookie", cookie.getValue())
                    .build();
            txn.update(cookieEntity);
            txn.commit();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }

public static boolean isCookieValid(String idCooKie,String cooKieValue) {
        Key userKey = userKeyFactory.newKey(idCooKie);
        Entity user = datastore.get(userKey);
        if (user == null) {
            return false;
        }
        return user.getString("cookie").equals(cooKieValue);
    }
}
