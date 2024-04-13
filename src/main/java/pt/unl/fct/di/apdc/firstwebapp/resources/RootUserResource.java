package pt.unl.fct.di.apdc.firstwebapp.resources;

import java.util.logging.Logger;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.codec.digest.DigestUtils;

import com.google.cloud.datastore.*;

@Path("/rootUser")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class RootUserResource {
    private static final Logger LOG = Logger.getLogger(RootUserResource.class.getName());
    private final static Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final static KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");

    public RootUserResource() {
    }

    @Path("/")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response registerRootUser() {

        Transaction txn = datastore.newTransaction();
        try {
            Key userKey = userKeyFactory.newKey("root");
            Entity user = txn.get(userKey);
            if (user != null) {
                return Response.status(Response.Status.CONFLICT).entity("{\"error\": \"Username is not available.\"}")
                        .build();
            }
            user = Entity.newBuilder(userKey)
                    .set("username", "root")
                    .set("password", DigestUtils.sha512Hex("root"))
                    .set("email", "root@gmail.com")
                    .set("name", "root")
                    .set("number", "123456789")
                    .set("role", "SU")
                    .set("state", "ACTIVE")
                    .set("profile", "PUBLIC")
                    .set("address", "root")
                    .set("occupation", "root")
                    .set("workplace", "root")
                    .set("postCode", "1234-567")
                    .set("nif", "123456789")
                    .set("imagePath", "root")
                    .build();
            txn.put(user);
            txn.commit();
            LOG.fine("Root registered successfully");
            return Response.ok().build();
        } catch (DatastoreException e) {
            LOG.severe("Error while registering root user: " + e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"error\": \"Error while registering root user. See logs.\"}")
                    .build();
        }
    }
}
