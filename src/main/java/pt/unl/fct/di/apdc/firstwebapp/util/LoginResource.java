package pt.unl.fct.di.apdc.firstwebapp.resources;

import java.util.UUID;
import java.util.logging.Logger;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import com.google.cloud.datastore.*;
import org.apache.commons.codec.digest.DigestUtils;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.Cookie;
import pt.unl.fct.di.apdc.firstwebapp.utils.LoginData;
import pt.unl.fct.di.apdc.firstwebapp.utils.RegisterData;
import pt.unl.fct.di.apdc.firstwebapp.Authentication.SignatureUtils;
import pt.unl.fct.di.apdc.firstwebapp.utils.*;

@Path("/login")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LoginResource {

    public static final String SU = "SU";
    public static final String GA = "GA";
    public static final String GBO = "GBO";
    public static final String USER = "USER";
    private static final String key = "dhsjfhndkjvnjdsdjhfkjdsjfjhdskjhfkjsdhfhdkjhkfajkdkajfhdkmc";
    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
    private final static Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    public LoginResource() {
    }

    @POST
    @Path("/")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response doLogin(LoginData data) {
        LOG.fine("Attempt to login user " + data.username);
        Key userKey = datastore.newKeyFactory().newKey(data.username);
        Entity user = datastore.get(userKey);
        if (user != null && checkPassword(data)) {
            String id = UUID.randomUUID().toString();
            long currentTime = System.currentTimeMillis();
            long expirationTime = currentTime + 1000 * 60 * 60 * 2;
            String role = user.getString("role");
            String fields = data.username + "." + id + "." + role + "." + currentTime + "." + expirationTime;

            String signature = SignatureUtils.calculateHMac(key, fields);

            if (signature == null) {
                return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Error while signing token. See logs.")
                        .build();
            }

            String value = fields + "." + signature;
            NewCookie cookie = new NewCookie("individual::apdc", value, "/", null, "comment", 1000 * 60 * 60 * 2,
                    false,
                    true);
            LOG.fine("User " + data.username + " logged in successfully");
            return Response.ok().cookie(cookie).build();

        }

        LOG.fine("Failed login attempt for user " + data.username);
        return Response.status(Response.Status.FORBIDDEN).entity("Incorrect username or password.").build();
    }

    @POST
    @Path("/logout")
    public Response doLogout(@CookieParam("individual::apdc") Cookie cookie) {
        if (cookie == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("No cookie found.").build();
        }
        String[] fields = cookie.getValue().split("\\.");
        if (fields.length != 6) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Invalid cookie.").build();
        }
        String signature = SignatureUtils.calculateHMac(key, fields[0] + "." + fields[1] + "." + fields[2] + "."
                + fields[3] + "." + fields[4]);
        if (signature == null) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Error while signing token. See logs.")
                    .build();
        }
        if (!signature.equals(fields[5])) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Invalid cookie.").build();
        }
        LOG.fine("User " + fields[0] + " logged out successfully");
        return Response.ok().cookie(new NewCookie(cookie, null, 0, false)).build();
    }

    private static boolean checkPassword(LoginData data) {
        LOG.fine("Checking password for user " + data.username);
        Key userKey = datastore.newKeyFactory().newKey(data.username);
        Entity user = datastore.get(userKey);
        String password = user.getString("password");
        if (user == null || !password.equals(DigestUtils.sha512Hex(data.password))) {
            return false;
        }
        return true;
    }

    @POST
    @Path("/register")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response registerUser(RegisterData data) {
        LOG.fine("Attempt to register user " + data.username);
        if (data.username == null || data.password == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Username and password are required.").build();
        }
        if (data.username.length() < 3 || data.username.length() > 20) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Username must be between 3 and 20 characters.")
                    .build();
        }
        if (data.password.length() < 8 || data.password.length() > 64) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Password must be between 8 and 64 characters.")
                    .build();
        }
        if (!data.isPasswordValid()) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Passwords do not match.").build();
        }
        if (!data.isEmailValid()) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Invalid email address.").build();
        }
        if (!data.isNumberValid()) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Invalid phone number.").build();
        }
        Transaction txn = datastore.newTransaction();
        try {
            Key userKey = datastore.newKeyFactory().newKey(data.username);
            Entity user = txn.get(userKey);
            if (user != null) {
                txn.rollback();
                return Response.status(Response.Status.CONFLICT).entity("Username is not available.").build();
            }
            user = Entity.newBuilder(userKey).set("username", data.username)
                    .set("password", DigestUtils.sha512Hex(data.password)).set("email", data.email)
                    .set("name", data.name)
                    .set("number", data.number).build();
            txn.add(user);
            txn.commit();
            LOG.fine("User " + data.username + " registered successfully");
            return Response.ok().build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }

    @GET
    @Path("/{username}")
    public Response checkUsernameAvailable(@PathParam("username") String username) {
        LOG.fine("Checking if username " + username + " is available");
        Key userKey = datastore.newKeyFactory().newKey(username);
        Entity user = datastore.get(userKey);
        if (user == null) {
            return Response.ok().build();
        }
        return Response.status(Response.Status.CONFLICT).build();
    }

    @POST
    @Path("/changePassword")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response changePassword(ChangePasswordData data) {
        LOG.fine("Attempt to change password for user " + data.username);
        if (data.username == null || data.oldPassword == null || data.newPassword == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Username and both passwords are required.")
                    .build();
        }
        if (!data.isPasswordValid()) {
            return Response.status(Response.Status.BAD_REQUEST).entity(
                    "Password must be at least 8 characters long and contain at least one digit, one lowercase letter, and one uppercase letter.")
                    .build();
        }
        if (!data.isPasswordMatch()) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Passwords do not match.").build();
        }
        Transaction txn = datastore.newTransaction();
        try {
            Key userKey = datastore.newKeyFactory().newKey(data.username);
            Entity user = txn.get(userKey);
            String password = user.getString("password");
            if (user == null || !password.equals(DigestUtils.sha512Hex(data.oldPassword))) {
                txn.rollback();
                return Response.status(Response.Status.FORBIDDEN).entity("Incorrect username or password.").build();
            }
            user = Entity.newBuilder(userKey).set("username", data.username)
                    .set("password", DigestUtils.sha512Hex(data.newPassword)).set("email", user.getString("email"))
                    .set("name", user.getString("name")).set("number", user.getString("number")).build();
            txn.update(user);
            txn.commit();
            LOG.fine("Password for user " + data.username + " changed successfully");
            return Response.ok().build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }

    @POST
    @Path("/delete")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response deleteUser(@CookieParam("individual::apdc") Cookie cookie, UserData data) {
        if (!checkPermissions(cookie, data.role)) {
            return Response.status(Response.Status.FORBIDDEN).entity("Insufficient permissions.").build();
        }
        LOG.fine("Attempt to delete user " + data.username);
        if (data.username == null || data.password == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Username and password are required.").build();
        }
        Transaction txn = datastore.newTransaction();
        try {
            Key userKey = datastore.newKeyFactory().newKey(data.username);
            Entity user = txn.get(userKey);
            String password = user.getString("password");
            if (user == null || !password.equals(DigestUtils.sha512Hex(data.password))) {
                txn.rollback();
                return Response.status(Response.Status.FORBIDDEN).entity("Incorrect username or password.").build();
            }
            txn.delete(userKey);
            txn.commit();
            LOG.fine("User " + data.username + " deleted successfully");
            return Response.ok().build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }

    public static boolean checkChangeRolePermissions(Cookie cookie) {

        String value = cookie.getValue();
        String[] values = value.split("\\.");
        int userInSessionRole = convertRole(values[2]);
        if (userInSessionRole <= 2) {
            return false;
        }
        return true;
    }

    public static boolean checkPermissions(Cookie cookie, String role) {
        if (cookie == null || cookie.getValue() == null) {
            return false;
        }

        String value = cookie.getValue();
        String[] values = value.split("\\.");

        String signatureNew = SignatureUtils.calculateHMac(key,
                values[0] + "." + values[1] + "." + values[2] + "." + values[3] + "." + values[4]);
        String signatureOld = values[5];

        if (!signatureNew.equals(signatureOld)) {
            return false;
        }

        int neededRole = convertRole(role);
        int userInSessionRole = convertRole(values[2]);

        if (userInSessionRole <= neededRole) {
            return false;
        }

        if (System.currentTimeMillis() > (Long.valueOf(values[3]) + Long.valueOf(values[4]) * 1000)) {

            return false;
        }

        return true;
    }

    private static int convertRole(String role) {
        int result = 0;
        switch (role) {
            case GBO:
                result = 1;
                break;
            case GA:
                result = 2;
                break;
            case USER:
                result = 0;
                break;
            case SU:
                result = 3;
                break;
            default:
                result = 0;
                break;
        }
        return result;
    }

    @POST
    @Path("/changeRole")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response changeRole(@CookieParam("individual::apdc") Cookie cookie, ChangeRoleData data) {
        if (data.username == null || data.role == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Username and role are required.").build();
        }
        Transaction txn = datastore.newTransaction();
        try {
            Key userKey = datastore.newKeyFactory().newKey(data.username);
            Entity user = txn.get(userKey);
            if (!checkPermissions(cookie, user.getString("role"))) {
                return Response.status(Response.Status.FORBIDDEN).entity("Insufficient permissions.").build();
            }
            if (!checkChangeRolePermissions(cookie)) {
                return Response.status(Response.Status.FORBIDDEN).entity("Insufficient permissions.").build();
            }
            if (data.isValid() == false) {
                return Response.status(Response.Status.BAD_REQUEST).entity("Invalid role.").build();
            }
            LOG.fine("Attempt to change role for user " + data.username);
            user = Entity.newBuilder(userKey).set("username", data.username).set("password", user.getString("password"))
                    .set("email", user.getString("email")).set("name", user.getString("name"))
                    .set("number", user.getString("number")).set("role", data.role).build();
            txn.update(user);
            txn.commit();
            LOG.fine("Role for user " + data.username + " changed successfully");
            return Response.ok().build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }

    @POST
    @Path("/changeState")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response changeState(@CookieParam("individual::apdc") Cookie cookie, ChangeStateData data) {
        if (data.username == null || data.state == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Username and state are required.").build();
        }
        Transaction txn = datastore.newTransaction();
        try {
            Key userKey = datastore.newKeyFactory().newKey(data.username);
            Entity user = txn.get(userKey);
            String value = cookie.getValue();
            String[] values = value.split("\\.");
            String role = values[2];
            if (role.equals("USER")) {
                return Response.status(Response.Status.FORBIDDEN).entity("Insufficient permissions.").build();
            }
            if (!checkPermissions(cookie, user.getString("role"))) {
                return Response.status(Response.Status.FORBIDDEN).entity("Insufficient permissions.").build();
            }
            LOG.fine("Attempt to change state for user " + data.username);
            user = Entity.newBuilder(userKey).set("username", data.username).set("password", user.getString("password"))
                    .set("email", user.getString("email")).set("name", user.getString("name"))
                    .set("number", user.getString("number")).set("role", user.getString("role"))
                    .set("state", data.state).build();
            txn.update(user);
            txn.commit();
            LOG.fine("State for user " + data.username + " changed successfully");
            return Response.ok().build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }

    @POST
    @Path("/changeProfile")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response changeProfile(@CookieParam("individual::apdc") Cookie cookie, ChangeProfileData data) {
        if (data.username == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Username is required.").build();
        }
        Transaction txn = datastore.newTransaction();
        try {
            Key userKey = datastore.newKeyFactory().newKey(data.username);
            Entity user = txn.get(userKey);
            if (user == null) {
                txn.rollback();
                return Response.status(Response.Status.NOT_FOUND).entity("User not found.").build();
            }
            if (!checkPermissions(cookie, user.getString("role"))) {
                return Response.status(Response.Status.FORBIDDEN).entity("Insufficient permissions.").build();
            }
            LOG.fine("Attempt to change profile for user " + data.username);
            if (!data.isEmailValid()) {
                return Response.status(Response.Status.BAD_REQUEST).entity("Invalid email address.").build();
            }
            if (!data.isNumberValid()) {
                return Response.status(Response.Status.BAD_REQUEST).entity("Invalid phone number.").build();
            }
            user = Entity.newBuilder(userKey).set("password", user.getString("password"))
                    .set("email", data.email != null ? data.email : user.getString("email"))
                    .set("name", data.name != null ? data.name : user.getString("name"))
                    .set("number", data.number != null ? data.number : user.getString("number"))
                    .set("role", user.getString("role")).set("state", user.getString("state")).build();
            txn.update(user);
            txn.commit();
            LOG.fine("Profile for user " + data.username + " changed successfully");
            return Response.ok().build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }

}