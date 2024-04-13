package pt.unl.fct.di.apdc.firstwebapp.resources;

import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import javax.ws.rs.core.Cookie;

import com.google.appengine.api.users.User;
import com.google.cloud.datastore.*;
import com.google.gson.Gson;

import pt.unl.fct.di.apdc.firstwebapp.Authentication.SignatureUtils;
import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.CookieOperations;
import pt.unl.fct.di.apdc.firstwebapp.util.LogoutData;
import pt.unl.fct.di.apdc.firstwebapp.util.PermissionsTools;
import pt.unl.fct.di.apdc.firstwebapp.util.UserData;

@Path("/list")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class ListUsersResource {
    private static final String key = "dhsjfhndkjvnjdsdjhfkjdsjfjhdskjhfkjsdhfhdkjhkfajkdkajfhdkmc";
    private final static Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final static KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
    private final Gson gson = new Gson();

    public ListUsersResource() {
    }

    @Path("/")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
    public Response listUsers(LogoutData data) {

        if (data.cookie == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Cookie not found").build();
        }

        // Extrair informações do cookie
        String cookieValue = data.cookie;
        String[] parts = cookieValue.split("\\."); // Dividir o cookie em partes
        if (parts.length != 6) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Invalid cookie format").build();
        }

        // Verificar a assinatura HMAC do cookie
        String signature = parts[5];
        String tokenString = parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3] + "." + parts[4];

        if (!SignatureUtils.verifyHMac(key, tokenString, signature)) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Invalid signature").build();
        }
        if (!CookieOperations.isCookieValid(parts[0], cookieValue)) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Invalid cookie").build();
        }

        // Verificar se o token é válido
        if (AuthToken.isTokenExpired(Long.parseLong(parts[4]))) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Expired token").build();
        }

        Key userKey = userKeyFactory.newKey(parts[0]);
        Entity user = datastore.get(userKey);
        if (user == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("User not found").build();
        }
        String userRole = user.getString("role");

        List<Entity> allowedUsers = new ArrayList<>();
        List<Entity> users = new ArrayList<>();

        Query<Entity> query = Query.newEntityQueryBuilder().setKind("User").build();
        QueryResults<Entity> results = datastore.run(query);

        if ("USER".equals(userRole)) {
            StructuredQuery.Filter compositeFilter = StructuredQuery.CompositeFilter.and(
                    StructuredQuery.PropertyFilter.eq("role", "USER"),
                    StructuredQuery.PropertyFilter.eq("profile", "PUBLIC"),
                    StructuredQuery.PropertyFilter.eq("state", "ACTIVE"));

            Query<Entity> query2 = Query.newEntityQueryBuilder()
                    .setKind("User")
                    .setFilter(compositeFilter)
                    .build();

            results = datastore.run(query2);
        }

        while (results.hasNext()) {
            Entity entity = results.next();
            String userRoleTarget = entity.getString("role");
            String targetRole = userRoleTarget;

            if (PermissionsTools.canSeeUser(userRole, targetRole)) {
                if (userRole.equals("USER")) {
                    Key userKey2 = userKeyFactory.newKey(entity.getString("username"));
                    Entity userEntity=  Entity.newBuilder(userKey2)
                            .set("username", entity.getString("username"))
                            .set("email", entity.getString("email"))
                            .set("name", entity.getString("name"))
                            .build();
                    users.add(userEntity);
                } else {
                    allowedUsers.add(entity);
                }
            }
        }
        if (userRole.equals("USER"))
            return Response.ok(gson.toJson(users)).build();
        else
            return Response.ok(gson.toJson(allowedUsers)).build();
    }
}
