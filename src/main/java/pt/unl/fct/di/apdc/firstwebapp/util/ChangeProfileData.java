package pt.unl.fct.di.apdc.firstwebapp.util;

public class ChangeProfileData {

    public String username;
    public String email;
    public String name;
    public String number;

    public ChangeProfileData() {

    }

    public ChangeProfileData(String username, String email, String name, String number) {
        this.username = username;
        this.email = email;
        this.name = name;
        this.number = number;
    }

    public boolean isValid() {
        return username != null && email != null && name != null && number != null;
    }

    public boolean isEmailValid() {
        return email != null && email.contains("@") && email.contains(".");
    }

    public boolean isNumberValid() {
        return number != null && number.length() == 9;
    }

}
