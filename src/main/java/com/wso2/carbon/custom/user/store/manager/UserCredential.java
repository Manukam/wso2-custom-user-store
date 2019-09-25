package com.wso2.carbon.custom.user.store.manager;

public class UserCredential {

    String userName;
    Object password;

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public Object getPassword() {
        return password;
    }

    public void setPassword(Object password) {
        this.password = password;
    }
}
