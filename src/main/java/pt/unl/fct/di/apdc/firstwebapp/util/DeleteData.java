package pt.unl.fct.di.apdc.firstwebapp.util;

public class DeleteData {

    public String username;
    public String cookie;

    public DeleteData() {

    }

    public DeleteData(String username, String cookie) {
        this.username = username;
        this.cookie = cookie;
    }

    public boolean isValid() {
        return username.equals("");
    }

}
