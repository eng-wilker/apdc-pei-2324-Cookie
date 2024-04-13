package pt.unl.fct.di.apdc.firstwebapp.resources;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Cookie;

import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.ChangeRoleData;
import pt.unl.fct.di.apdc.firstwebapp.util.CookieOperations;
import pt.unl.fct.di.apdc.firstwebapp.util.PermissionsTools;
import pt.unl.fct.di.apdc.firstwebapp.Authentication.SignatureUtils;

import com.google.cloud.datastore.*;

@Path("/changePermition")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class ChangeRoleResource {
    public static final String SU = "SU";
    public static final String GA = "GA";
    public static final String GBO = "GBO";
    public static final String USER = "USER";
    private static final String key = "dhsjfhndkjvnjdsdjhfkjdsjfjhdskjhfkjsdhfhdkjhkfajkdkajfhdkmc";
    private final static Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final static KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");

    public ChangeRoleResource() {
    }

    @Path("/")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response changePermission(ChangeRoleData data) {
        if (data.cookie == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("{\"error\": \"Cookie not found\"}").build();
        }

        // Extrair informações do cookie
        String cookieValue = data.cookie;
        String[] parts = cookieValue.split("\\."); // Dividir o cookie em partes
        if (parts.length != 6) {
            return Response.status(Response.Status.BAD_REQUEST).entity("{\"error\": \"Invalid cookie format\"}")
                    .build();
        }

        // Verificar a assinatura HMAC do cookie
        String tokenString = parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3] + "." + parts[4];
        String signature = parts[5];
        if (!SignatureUtils.verifyHMac(key, tokenString, signature)) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("{\"error\": \"Invalid signature\"}").build();
        }

        if (!CookieOperations.isCookieValid(parts[0], cookieValue)) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("{\"error\": \"Invalid cookie\"}").build();
        }

        // Converter a string do token para AuthToken
        if (AuthToken.isTokenExpired(Long.parseLong(parts[4]))) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("{\"error\": \"Expired token\"}").build();
        }

        Transaction txn = datastore.newTransaction();
        Key userKey = userKeyFactory.newKey(data.username);
        Entity user = datastore.get(userKey);
        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND).entity("{\"error\": \"User not found\"}").build();
        }

        try {
            // Verificar se a permissão é válida
            if (!data.isValidRole()) {
                return Response.status(Response.Status.BAD_REQUEST).entity("{\"error\": \"Invalid role\"}").build();
            }

            // Verificar se o usuário tem permissão para alterar a permissão
            if (!PermissionsTools.canModifyRole(parts[2], user.getString("role"), data.role)) {
                return Response.status(Response.Status.FORBIDDEN).entity("{\"error\": \"Permission denied\"}").build();
            }

            // Alterar a permissão
            Entity updatedUser = Entity.newBuilder(user)
                    .set("role", data.role)
                    .build();
            datastore.update(updatedUser);
            txn.commit();

            return Response.ok().entity("{\"message\": \"Role changed successfully\"}").build();
        } catch (Exception e) {
            txn.rollback();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"error\": \"Error while changing user role. See logs.\"}").build();
        }
    }
}
