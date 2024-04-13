package pt.unl.fct.di.apdc.firstwebapp.resources;

import javax.ws.rs.*;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;

import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.CookieOperations;
import pt.unl.fct.di.apdc.firstwebapp.Authentication.SignatureUtils;
import pt.unl.fct.di.apdc.firstwebapp.util.LogoutData;

@Path("/logout")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LogOutResource {

    private static final String COOKIE_NAME = "individual::apdc";
    private static final String HMAC_KEY = "dhsjfhndkjvnjdsdjhfkjdsjfjhdskjhfkjsdhfhdkjhkfajkdkajfhdkmc";

    @POST
    public Response doLogout(LogoutData data) {
        if (data.cookie == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Cookie not found").build();
        }

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

        if (!SignatureUtils.verifyHMac(HMAC_KEY , tokenString, signature)) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("{\"error\": \"Invalid signature\"}").build();
        }
        if (!CookieOperations.isCookieValid(parts[0], cookieValue)) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("{\"error\": \"Invalid cookie\"}").build();
        }

        // Verificar se o token é válido
        if (AuthToken.isTokenExpired(Long.parseLong(parts[4]))) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("{\"error\": \"Expired token\"}").build();
        }

        // Remover o cookie do banco de dados
        CookieOperations.deleteCookie(parts[0]);

        // Criar um novo cookie expirado para substituir o cookie antigo no cliente
        return Response.ok().cookie(new NewCookie(COOKIE_NAME, "", "/", null, "comment", 0, false, true)).build();
    }
}
