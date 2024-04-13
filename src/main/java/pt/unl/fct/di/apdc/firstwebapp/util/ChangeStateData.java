package pt.unl.fct.di.apdc.firstwebapp.util;

public class ChangeStateData {

    public String username;
    public String state;
    public String cookie;

    public ChangeStateData() {

    }

    public ChangeStateData(String username, String state, String cookie) {
        this.username = username;
        this.state = state.toUpperCase();
        this.cookie = cookie;
    }

    public boolean isValid() {
        return !username.equals("") && !state.equals("") && (state.equals("ACTIVE") || state.equals("INACTIVE"));
    }

}
