package pt.unl.fct.di.apdc.firstwebapp.resources;

import java.util.logging.Logger;
import javax.ws.rs.*;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.commons.codec.digest.DigestUtils;
import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.ChangePasswordData;
import pt.unl.fct.di.apdc.firstwebapp.util.CookieOperations;
import pt.unl.fct.di.apdc.firstwebapp.Authentication.SignatureUtils;
import com.google.gson.Gson;

import com.google.cloud.datastore.*;

@Path("/changePassword")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class ChangePasswordResource {
    private static final Logger LOG = Logger.getLogger(ChangePasswordResource.class.getName());
    private final static Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final static KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
    private static final String key = "dhsjfhndkjvnjdsdjhfkjdsjfjhdskjhfkjsdhfhdkjhkfajkdkajfhdkmc";
    private final Gson g = new Gson();

    public ChangePasswordResource() {
    }

    @Path("/")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response changePassword(ChangePasswordData data) {
        if (data.cookie == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("{\"error\": \"Cookie not found\"}").build();
        }

        // Extrair informações do cookie
        String cookieValue = data.cookie;
        String[] parts = cookieValue.split("\\."); // Dividir o cookie em partes
        if (parts.length != 6) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\": \"invalid cookie format\"}").build();

        }

        // Verificar a assinatura HMAC do cookie
        String tokenString = parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3] + "." + parts[4];
        String signature = parts[5];
        if (!SignatureUtils.verifyHMac(key, tokenString, signature)) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("{\"error\": \"Invalid signature\"}").build();
        }

        // Converter a string do token para AuthToken
        if (!CookieOperations.isCookieValid(parts[0], cookieValue)) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("{\"error\": \"Invalid cookie\"}").build();
        }
        // Verifica se o token expirou
        if (AuthToken.isTokenExpired(Long.parseLong(parts[4]))) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("{\"error\": \"Expired token\"}").build();
        }

        // Buscar o usuário na Datastore
        Key userKey = userKeyFactory.newKey(parts[0]);
        Entity user = datastore.get(userKey);

        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("{\"error\": \"User not found\"}").build();
        }

        // Verificar a senha atual do usuário
        String currentPasswordHash = DigestUtils.sha512Hex(data.oldPassword);
        String storedPasswordHash = user.getString("password");
        if (!currentPasswordHash.equals(storedPasswordHash)) {
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("{\"error\": \"Wrong password\"}").build();
        }
        Entity userEntity = datastore.get(userKey);

        // Modificar apenas a senha na entidade carregada
        String newPasswordHashed = DigestUtils.sha512Hex(data.newPassword);
        userEntity = Entity.newBuilder(userEntity)
                .set("password", newPasswordHashed)
                .build();

        // Atualizar a entidade na Datastore
        Transaction txn = datastore.newTransaction();
        try {
            txn.update(userEntity);
            txn.commit();
            return Response.ok().entity("{\"message\": \"Password changed successfully\"}").build();
        } catch (Exception e) {
            LOG.severe(e.getMessage());
            txn.rollback();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"error\": \"Error while changing password. See logs.\"}").build();
        }

    }

}
