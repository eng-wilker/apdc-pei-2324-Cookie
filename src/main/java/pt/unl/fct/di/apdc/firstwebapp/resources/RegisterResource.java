package pt.unl.fct.di.apdc.firstwebapp.resources;

import java.util.logging.Logger;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.codec.digest.DigestUtils;

import pt.unl.fct.di.apdc.firstwebapp.util.RegisterData;

import com.google.cloud.datastore.*;
@Path("/register")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class RegisterResource {
    private static final Logger LOG = Logger.getLogger(RegisterResource.class.getName());
    private final static Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final static KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");

    public RegisterResource() {
    }

    @Path("/")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response registerUser(RegisterData data) {
        LOG.fine("Attempt to register user " + data.username);
        if (!data.isValid()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\": \"username, password, email, name, number cannot be null\"}").build();
        }
        if (data.username.length() < 3 || data.username.length() > 20) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\": \"Username must be between 3 and 20 characters.\"}")
                    .build();
        }
        if (data.password.length() < 8 || data.password.length() > 64) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\": \"Password must be between 8 and 64 characters.\"}")
                    .build();
        }
        if (!data.isPasswordValid()) {
            return Response.status(Response.Status.BAD_REQUEST).entity("{\"error\": \"Invalid Passwords.\"}").build();
        }
        if (!data.isEmailValid()) {
            return Response.status(Response.Status.BAD_REQUEST).entity("{\"error\": \"Invalid email address.\"}")
                    .build();
        }
        if (!data.isNumberValid()) {
            return Response.status(Response.Status.BAD_REQUEST).entity("{\"error\": \"Invalid phone number.\"}")
                    .build();
        }
        if (data.isProfileValid() == false) {
            return Response.status(Response.Status.BAD_REQUEST).entity("{\"error\": \"Invalid profile.\"}").build();
        }

        Transaction txn = datastore.newTransaction();
        try {
            Key userKey = userKeyFactory.newKey(data.username);
            Entity user = txn.get(userKey);
            if (user != null) {
                return Response.status(Response.Status.CONFLICT).entity("{\"error\": \"Username is not available.\"}")
                        .build();
            }
            user = Entity.newBuilder(userKey)
                    .set("username", data.username)
                    .set("password", DigestUtils.sha512Hex(data.password))
                    .set("email", data.email)
                    .set("name", data.name)
                    .set("number", data.number)
                    .set("role", "USER")
                    .set("state", data.state)
                    .set("profile", data.profile.toUpperCase())
                    .set("address", data.address)
                    .set("occupation", data.occupation)
                    .set("workplace", data.workplace)
                    .set("postCode", data.postCode)
                    .set("nif", data.nif)
                    .set("imagePath", data.imagePath)
                    .build();
            txn.add(user);
            txn.commit();
            LOG.fine("User " + data.username + " registered successfully");
            return Response.ok().build();
        } catch (DatastoreException e) {
            LOG.severe("Error while registering user: " + e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"error\": \"Error while registering user. See logs.\"}")
                    .build();
        }
    }
}
