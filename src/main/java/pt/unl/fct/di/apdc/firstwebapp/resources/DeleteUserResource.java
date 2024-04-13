package pt.unl.fct.di.apdc.firstwebapp.resources;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import javax.ws.rs.core.Cookie;

import com.google.cloud.datastore.*;

import pt.unl.fct.di.apdc.firstwebapp.Authentication.SignatureUtils;
import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.CookieOperations;
import pt.unl.fct.di.apdc.firstwebapp.util.PermissionsTools;
import pt.unl.fct.di.apdc.firstwebapp.util.DeleteData;

@Path("/deleteUser")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class DeleteUserResource {
    private final static Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final static KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
    private static final String key = "dhsjfhndkjvnjdsdjhfkjdsjfjhdskjhfkjsdhfhdkjhkfajkdkajfhdkmc";

    public DeleteUserResource() {
    }

    @Path("/")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
    public Response deleteUser(DeleteData data) {
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

        String signature = parts[5];
        String tokenString = parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3] + "." + parts[4];

        if (!SignatureUtils.verifyHMac(key, tokenString, signature)) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("{\"error\": \"Invalid signature\"}").build();
        }
        if (!CookieOperations.isCookieValid(parts[0], cookieValue)) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("{\"error\": \"Invalid cookie\"}").build();
        }

        // Verificar se o token é válido
        if (AuthToken.isTokenExpired(Long.parseLong(parts[4]))) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("{\"error\": \"Expired token\"}").build();
        }

        // Verificar se o utilizador tem permissões para apagar a conta
        // Apagar a conta
        Key userKey = userKeyFactory.newKey(data.username);
        Entity user = datastore.get(userKey);
        if (!PermissionsTools.canRemoveUser(parts[2], user.getString("role"), parts[0], user.getString("username"))) {
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("{\"error\": \"User does not have permission to delete this account.\"}")
                    .build();
        }
        CookieOperations.deleteCookie(data.username);
        datastore.delete(userKey);
        return Response.ok().entity("{\"message\": \"Account deleted successfully\"}").build();

    }
}
