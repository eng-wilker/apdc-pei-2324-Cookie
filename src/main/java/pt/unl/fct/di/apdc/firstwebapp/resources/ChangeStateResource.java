package pt.unl.fct.di.apdc.firstwebapp.resources;

import java.util.logging.Logger;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Cookie;
import com.google.cloud.datastore.*;
import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.ChangeStateData;
import pt.unl.fct.di.apdc.firstwebapp.util.CookieOperations;
import pt.unl.fct.di.apdc.firstwebapp.util.PermissionsTools;
import pt.unl.fct.di.apdc.firstwebapp.Authentication.SignatureUtils;

@Path("/changeState")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class ChangeStateResource {

    private final static Logger LOG = Logger.getLogger(ChangeStateResource.class.getName());
    private final static Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final static KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
    private static final String key = "dhsjfhndkjvnjdsdjhfkjdsjfjhdskjhfkjsdhfhdkjhkfajkdkajfhdkmc";

    public ChangeStateResource() {
    }

    @Path("/")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
    public Response changeState(ChangeStateData data) {
        if (data.cookie == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("{\"error\": \"Cookie not found\"}").build();
        }

        // Extrair informações do cookie
        String cookieValue = data.cookie;
        String[] parts = cookieValue.split("\\."); // Dividir o cookie em partes
        if (parts.length != 6) {
            return Response.status(Response.Status.BAD_REQUEST).entity("{\"error\": \"Invalid cookie format\"}").build();
        }

        // Verificar a assinatura HMAC do cookie
        String tokenString = String.join(".", parts[0], parts[1], parts[2], parts[3], parts[4]);
        if (!SignatureUtils.verifyHMac(key, tokenString, parts[5])) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("{\"error\": \"Invalid signature\"}").build();
        }
        if (!CookieOperations.isCookieValid(parts[0], cookieValue)) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("{\"error\": \"Invalid cookie\"}").build();
        }

        // Converter a string do token para AuthToken
        if (AuthToken.isTokenExpired(Long.parseLong(parts[4]))) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("{\"error\": \"Expired token\"}").build();
        }

        // Verificar se o usuário tem permissão para alterar o estado
        Transaction txn = datastore.newTransaction();
        try {
            Key userKey = userKeyFactory.newKey(data.username);
            Entity user = txn.get(userKey);
            if (user == null) {
                return Response.status(Response.Status.BAD_REQUEST).entity("{\"error\": \"User not found\"}").build();
            }
            String userRole = user.getString("role");
            if (!PermissionsTools.canModifyState(parts[2], userRole)) {
                return Response.status(Response.Status.FORBIDDEN).entity("{\"error\": \"Insufficient permissions\"}").build();
            }

            // Alterar o estado do usuário
            user = Entity.newBuilder(user)
                    .set("state", data.state)
                    .build();
            txn.update(user);

            // Excluir o cookie
            CookieOperations.deleteCookie(data.username);

            txn.commit();
            return Response.ok().entity("{\"message\": \"State changed successfully\"}").build();
        } catch (DatastoreException e) {
            LOG.severe("Error while changing state: " + e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"error\": \"Error while changing state. See logs.\"}").build();
        }
    }
}
