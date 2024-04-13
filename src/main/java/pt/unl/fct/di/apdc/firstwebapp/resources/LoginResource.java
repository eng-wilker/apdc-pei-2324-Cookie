
package pt.unl.fct.di.apdc.firstwebapp.resources;

import javax.ws.rs.*;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;

import org.apache.commons.codec.digest.DigestUtils;
import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.CookieOperations;
import pt.unl.fct.di.apdc.firstwebapp.util.LoginData;
import pt.unl.fct.di.apdc.firstwebapp.Authentication.SignatureUtils;
import com.google.cloud.datastore.*;
import com.google.gson.Gson;

import java.util.logging.Logger;

@Path("/login")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LoginResource {

    private static final String key = "dhsjfhndkjvnjdsdjhfkjdsjfjhdskjhfkjsdhfhdkjhkfajkdkajfhdkmc";
    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
    private final static Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final static KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
    private final Gson g = new Gson();

    public LoginResource() {
    }


    @Path("/")
    @POST
    @Consumes(MediaType.APPLICATION_JSON + ";charset=utf-8")
    @Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
    public Response doLogin(LoginData data) {
        LOG.fine("Attempt to login user " + data.username);
        try {
            Key userKey = userKeyFactory.newKey(data.username);
            Entity user = datastore.get(userKey);
            if (user == null) {
                LOG.fine("Failed login attempt for user " + data.username);
                return Response.status(Response.Status.FORBIDDEN).entity("{\"error\": \"Incorrect username or password.\"}").build();
            }
            if (user.getString("state").equals("INACTIVE")) {
                LOG.fine("Failed login attempt for user " + data.username);
                return Response.status(Response.Status.FORBIDDEN).entity("{\"error\": \"User is inactive.\"}").build();
            }

            if (checkPassword(data, user)) {
                String role = user.getString("role");
                AuthToken token = new AuthToken(data.username, role);
                String signature = SignatureUtils.calculateHMac(key, token.getFields());

                if (signature == null) {
                    return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                            .entity("{\"error\": \"Error while signing token.\"}").build();
                }

                String value = token.getFields() + "." + signature;
                NewCookie cookie = new NewCookie("individual::apdc", value, "/", null, "comment",
                        1000 * 60 * 60 * 2, false, true);

                // Adiciona cabeçalhos CORS para permitir solicitações entre origens
                // Response.ResponseBuilder responseBuilder = Response.ok().cookie(cookie);

                // Salva o cookie no banco de dados para futura verificação
                CookieOperations.registerCookie(data.username, cookie);

                // Adiciona o valor do cookie ao corpo da resposta
                //
                // Retorna a resposta
                Response response = Response.ok().entity(g.toJson(cookie)).cookie(cookie).build();
                return response;
            }

            LOG.fine("Failed login attempt for user " + data.username);
            return Response.status(Response.Status.FORBIDDEN).entity("{\"error\": \"Incorrect username or password.\"}")
                    .build();
        } catch (DatastoreException e) {
            LOG.severe("Error while logging in user: " + e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"error\": \"Error while logging in user. See logs.\"}").build();
        }
    }

    private static boolean checkPassword(LoginData data, Entity user) {
        LOG.fine("Checking password for user " + data.username);
        String password = user.getString("password");
        return password != null && password.equals(DigestUtils.sha512Hex(data.password));
    }
}
