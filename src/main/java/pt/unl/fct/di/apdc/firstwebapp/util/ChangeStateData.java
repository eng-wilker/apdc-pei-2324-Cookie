package pt.unl.fct.di.apdc.firstwebapp.util;

public class ChangeStateData {

    public String username;
    public String state;

    public ChangeStateData() {

    }

    public ChangeStateData(String username, String state) {
        this.username = username;
        this.state = state;
    }

    public boolean isValid() {
        return username != null && state != null && (state.equals("active") || state.equals("inactive"));
    }

}
