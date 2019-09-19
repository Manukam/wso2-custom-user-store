package com.wso2.custom.usermgt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.jdbc.JDBCUserStoreManager;
import org.wso2.carbon.user.core.ldap.ActiveDirectoryUserStoreManager;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Map;

public class CustomUserStoreManager extends ActiveDirectoryUserStoreManager {
    private static Log log = LogFactory.getLog(CustomUserStoreManager.class);
    // This instance is used to generate the hash values


    // You must implement at least one constructor
    public CustomUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties, ClaimManager
            claimManager, ProfileConfigurationManager profileManager, UserRealm realm, Integer tenantId)
            throws UserStoreException {
        super(realmConfig, properties, claimManager, profileManager, realm, tenantId);
        log.info("CustomUserStoreManager initialized...");
    }

    @Override
    protected boolean checkUserPasswordValid(Object credential) throws UserStoreException {
        return true;
    }

}