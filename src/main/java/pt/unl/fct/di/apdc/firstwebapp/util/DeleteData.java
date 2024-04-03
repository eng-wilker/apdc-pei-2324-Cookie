package pt.unl.fct.di.apdc.firstwebapp.util;


public class DeleteData {

    public String username;
    public String password;

    public DeleteData() {

    }

    public DeleteData(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public boolean isValid() {
        return username != null && password != null;
    }

}
