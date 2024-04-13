
package pt.unl.fct.di.apdc.firstwebapp.resources;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.codec.digest.DigestUtils;

import javax.ws.rs.core.Cookie;

import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.ChangeProfileData;
import pt.unl.fct.di.apdc.firstwebapp.util.CookieOperations;
import pt.unl.fct.di.apdc.firstwebapp.util.PermissionsTools;
import pt.unl.fct.di.apdc.firstwebapp.Authentication.SignatureUtils;

import com.google.cloud.datastore.*;

@Path("/changeProfileData")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class ChangeProfileDataResource {

    private final static Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final static KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
    private static final String key = "dhsjfhndkjvnjdsdjhfkjdsjfjhdskjhfkjsdhfhdkjhkfajkdkajfhdkmc";

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
    public Response changeProfileData(ChangeProfileData data) {
        if (data.cookie == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("{\"error\": \"Cookie not found\"}")
                    .build();
        }

        String cookieValue = data.cookie;
        String[] parts = cookieValue.split("\\.");

        if (parts.length != 6) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\": \"Invalid cookie format\"}")
                    .build();
        }

        String tokenString = parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3] + "." + parts[4];
        String signature = parts[5];
        if (!SignatureUtils.verifyHMac(key, tokenString, signature)) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("{\"error\": \"Invalid signature\"}")
                    .build();
        }

        if (!CookieOperations.isCookieValid(parts[0], cookieValue)) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("{\"error\": \"Invalid cookie\"}")
                    .build();
        }

        if (AuthToken.isTokenExpired(Long.parseLong(parts[4]))) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("{\"error\": \"Expired token\"}")
                    .build();
        }
        if (!data.isStateValid()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\": \"Invalid state\"}")
                    .build();
        }

        if (!data.isProfileValid()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\": \"Invalid profile\"}")
                    .build();
        }

        if (!data.isRoleValid()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\": \"Invalid role\"}")
                    .build();
        }

        Transaction txn = datastore.newTransaction();
        Key userKey = userKeyFactory.newKey(parts[0]);
        Entity user = datastore.get(userKey);

        if (user == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\": \"User not found\"}")
                    .build();
        }

        Key targetUserKey = userKeyFactory.newKey(data.targetUser);
        Entity targetUser = datastore.get(targetUserKey);

        if (targetUser == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("{\"error\": \"Target user not found\"}")
                    .build();
        }

        if (parts[2].equals("USER")) {
            if (!parts[0].equals(data.targetUser)) {
                return Response.status(Response.Status.FORBIDDEN)
                        .entity("{\"error\": \"User does not have permission to change profile\"}")
                        .build();
            }

            Entity updatedUser = Entity.newBuilder(targetUserKey)
                    .set("password",
                            data.password != null ? DigestUtils.sha512Hex(data.password)
                                    : targetUser.getString("password"))
                    .set("email", targetUser.getString("email"))
                    .set("name", targetUser.getString("name"))
                    .set("number", !data.number.equals("") ? data.number : targetUser.getString("number"))
                    .set("profile",
                            !data.profile.equals("") ? data.profile.toUpperCase() : targetUser.getString("profile"))
                    .set("occupation",
                            !data.occupation.equals("") ? data.occupation : targetUser.getString("occupation"))
                    .set("workplace", !data.workplace.equals("") ? data.workplace : targetUser.getString("workplace"))
                    .set("address", !data.address.equals("") ? data.address : targetUser.getString("address"))
                    .set("postCode", !data.postCode.equals("") ? data.postCode : targetUser.getString("postCode"))
                    .set("nif", !data.nif.equals("") ? data.nif : targetUser.getString("nif"))
                    .set("imagePath", !data.imagePath.equals("") ? data.imagePath : targetUser.getString("imagePath"))
                    .set("state", targetUser.getString("state"))
                    .set("username", targetUser.getString("username"))
                    .set("role", targetUser.getString("role"))
                    .build();
            txn.update(updatedUser);
            txn.commit();
            return Response.ok().entity("{\"message\": \"Profile data updated\"}").build();
        } else {
            if (!PermissionsTools.canModifyUser(parts[2], targetUser.getString("role"))) {
                return Response.status(Response.Status.FORBIDDEN)
                        .entity("{\"error\": \"User does not have permission to change profile\"}")
                        .build();
            } else {
                user = Entity.newBuilder(targetUserKey)
                        .set("password",
                                !data.password.equals("") ? DigestUtils.sha512Hex(data.password)
                                        : targetUser.getString("password"))
                        .set("email", !data.email.equals("") ? data.email : targetUser.getString("email"))
                        .set("username", targetUser.getString("username"))
                        .set("state", !data.state.equals("") ? data.state : targetUser.getString("state"))
                        .set("name", !data.name.equals("") ? data.name : targetUser.getString("name"))
                        .set("number", !data.number.equals("") ? data.number : targetUser.getString("number"))
                        .set("profile",
                                !data.profile.equals("") ? data.profile.toUpperCase() : targetUser.getString("profile"))
                        .set("address", !data.address.equals("") ? data.address : targetUser.getString("address"))
                        .set("occupation",
                                !data.occupation.equals("") ? data.occupation : targetUser.getString("occupation"))
                        .set("workplace",
                                !data.workplace.equals("") ? data.workplace : targetUser.getString("workplace"))
                        .set("postCode", !data.postCode.equals("") ? data.postCode : targetUser.getString("postCode"))
                        .set("nif", !data.nif.equals("") ? data.nif : targetUser.getString("nif"))
                        .set("imagePath",
                                !data.imagePath.equals("") ? data.imagePath : targetUser.getString("imagePath"))
                        .set("role", !data.role.equals("") ? data.role.toUpperCase() : targetUser.getString("role"))
                        .build();
                txn.update(user);
                txn.commit();
                return Response.ok().entity("{\"message\": \"Profile data updated\"}").build();
            }
        }
    }
}
