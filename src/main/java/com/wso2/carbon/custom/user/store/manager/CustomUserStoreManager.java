package com.wso2.carbon.custom.user.store.manager;

import org.apache.axiom.om.util.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.ldap.ActiveDirectoryUserStoreManager;
import org.wso2.carbon.user.core.ldap.ReadWriteLDAPUserStoreManager;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;
import org.wso2.carbon.user.core.util.DatabaseUtil;
import org.wso2.carbon.user.core.util.JNDIUtil;
import org.wso2.carbon.utils.Secret;
import org.wso2.carbon.utils.UnsupportedSecretTypeException;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.*;
import java.util.*;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CustomUserStoreManager extends ActiveDirectoryUserStoreManager {
    private static Log log = LogFactory.getLog(CustomUserStoreManager.class);
    private boolean isSSLConnection = false;

    // You must implement at least one constructor
    public CustomUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties, ClaimManager
            claimManager, ProfileConfigurationManager profileManager, UserRealm realm, Integer tenantId)
            throws UserStoreException {
        super(realmConfig, properties, claimManager, profileManager, realm, tenantId);
        log.info("CustomUserStoreManager initialized...");
    }

    private boolean isFormatCorrect(String regularExpression, char[] attribute) {
        CharBuffer charBuffer = CharBuffer.wrap(attribute);
        Pattern p2 = Pattern.compile(regularExpression);
        Matcher m2 = p2.matcher(charBuffer);
        boolean matches = m2.find();
        return matches;
    }

    private boolean isCaseSensitiveUsername() {
        String isUsernameCaseInsensitiveString = this.realmConfig.getUserStoreProperty("CaseInsensitiveUsername");
        return !Boolean.parseBoolean(isUsernameCaseInsensitiveString);
    }

//    @Override
//    public void doUpdateCredentialByAdmin(String userName, Object newCredential) throws UserStoreException {
//        log.info("Custom update policy");
//        String sqlStmt;
//        Connection dbConnection = null;
//        ResultSet rs = null;
//        PreparedStatement prepStmt = null;
//        String sqlstmt = null;
//        boolean regMatchCapital;
//        boolean regMatchSimple;
//        boolean regMatchNumber;
//        boolean regMatchSpecialChar;
//
//        ArrayList usrAttrValues = new ArrayList();
//        int validityCount = 0;
//        ArrayList<Boolean> regExValidationCount = new ArrayList();
//        if (this.isCaseSensitiveUsername()) {
//            sqlStmt = this.realmConfig.getUserStoreProperty("UpdateUserPasswordSQL");
//        } else {
//            sqlStmt = this.realmConfig.getUserStoreProperty("UpdateUserPasswordSQLCaseInsensitive");
//        }
//
//        try {
////            dbConnection = this.getDBConnection();
////            dbConnection.setAutoCommit(false);
////            sqlstmt = this.realmConfig.getUserStoreProperty("SelectUserSQL");
////            prepStmt = dbConnection.prepareStatement(sqlstmt);
////            prepStmt.setString(1, userName);
////            if (sqlstmt.contains("UM_TENANT_ID")) {
////                prepStmt.setInt(2, this.tenantId);
////            }
////            log.info(prepStmt);
////            rs = prepStmt.executeQuery();
////            if (rs.next()) {
////                Timestamp changedTime = rs.getTimestamp(6);
////                GregorianCalendar gc = new GregorianCalendar();
////                gc.add(10, -24);
////                Date date = gc.getTime();
////                if (!changedTime.before((date))) {
////                    log.info("Can not change password within 24 hours.");
////                    throw new UserStoreException("Can not change password within 24 hours.");
////                }
////            }
//
//            if (newCredential == null) {
////                return false;
//            } else {
//                Secret credentialObj;
//                try {
//                    credentialObj = Secret.getSecret(newCredential);
//                } catch (UnsupportedSecretTypeException var8) {
//                    throw new UserStoreException("Unsupported credential type", var8);
//                }
//
//                String[] specialWords = this.realmConfig.getUserStoreProperty("specialWords").split((","));
//                log.info("Loading Special Words");
//
//                if (Arrays.asList(specialWords).contains(String.valueOf(credentialObj.getChars()))) {
//                    log.info("Special Word Detected");
////                return false;
//                    throw new UserStoreException("Special Words detected in the password");
//                }
//
//                log.info("Loading User Attributes");
//                String[] properties = {"sn", "givenName"};
//                Map<String, String> userProperties = getUserPropertyValues(userName, properties, "default"); //More than one profile
////                log.info(userProperties.get("sn"));
//
//
//                for (String prop : properties) {
//                    usrAttrValues.add(userProperties.get(prop));
//                }
//
//                if (usrAttrValues.contains(String.valueOf(credentialObj.getChars()))) {
//                    log.info("Password contains user attribute values");
////                    handleUpdateCredentialFailure("301", "Password contains user attribute values", String.valueOf(credentialObj.getChars()))
////                    return false;
//                    throw new UserStoreException("Password contains user attribute values");
//                }
//
//                log.info("Loading Regular Expressions");
////                String regularExpression = this.realmConfig.getUserStoreProperty("PasswordJavaRegEx");
//                String regularCapitalExpression = this.realmConfig.getUserStoreProperty("PasswordCapitalJavaRegEx");
//                String regularSimpleExpression = this.realmConfig.getUserStoreProperty("PasswordSimpleJavaRegEx");
//                String regularNumberExpression = this.realmConfig.getUserStoreProperty("PasswordNumbersJavaRegEx");
//                String regularSpecialCharExpression = this.realmConfig.getUserStoreProperty("PasswordSpecialCharJavaRegEx");
////                var4 = regularExpression == null || this.isFormatCorrect(regularExpression, credentialObj.getChars());
//
//                regMatchCapital = regularCapitalExpression == null || this.isFormatCorrect(regularCapitalExpression, credentialObj.getChars());
//                regMatchSimple = regularSimpleExpression == null || this.isFormatCorrect(regularSimpleExpression, credentialObj.getChars());
//                regMatchNumber = regularNumberExpression == null || this.isFormatCorrect(regularNumberExpression, credentialObj.getChars());
//                regMatchSpecialChar = regularSpecialCharExpression == null || this.isFormatCorrect(regularSpecialCharExpression, credentialObj.getChars());
//
//                log.info("Capital Check: " + regMatchCapital);
//                log.info("Simple Check: " + regMatchSimple);
//                log.info("Number Check: " + regMatchNumber);
//                log.info("Special: " + regMatchSpecialChar);
//
//                regExValidationCount.add(regMatchCapital);
//                regExValidationCount.add(regMatchSimple);
//                regExValidationCount.add(regMatchNumber);
//                regExValidationCount.add(regMatchSpecialChar);
//
//                for (boolean validity : regExValidationCount) {
//                    if (validity) validityCount++;
//                }
//
//                if (validityCount < 3) {
//                    log.info("Regular Expression check failed");
////                    return false;
//                    throw new UserStoreException("Password doesn't meet the expected criteria");
//                }
//            }
//            log.info("Regular Expression check passsed");
//        } catch (SQLException var18) {
//            String saltValue2 = "Error occurred while retrieving user authentication info for user : " + userName;
//
//            if (log.isDebugEnabled()) {
//                log.debug(saltValue2, var18);
//            }
//        }
//        sqlStmt = null;
//        if (this.isCaseSensitiveUsername()) {
//            sqlStmt = this.realmConfig.getUserStoreProperty("UpdateUserPasswordSQL");
//        } else {
//            sqlStmt = this.realmConfig.getUserStoreProperty("UpdateUserPasswordSQLCaseInsensitive");
//        }
//
//
//    }

    @Override
    public void doUpdateCredentialByAdmin(String userName, Object newCredential) throws UserStoreException {
        log.info("Custom update policy");
        String sqlStmt;
        Connection dbConnection = null;
        ResultSet rs = null;
        PreparedStatement prepStmt = null;
        String sqlstmt = null;
        boolean regMatchCapital;
        boolean regMatchSimple;
        boolean regMatchNumber;
        boolean regMatchSpecialChar;

        ArrayList usrAttrValues = new ArrayList();
        int validityCount = 0;
        ArrayList<Boolean> regExValidationCount = new ArrayList();
        if (!this.isSSLConnection) {
            log.warn("Unsecured connection is being used. Password operations will fail");
        }

        DirContext dirContext = this.connectionSource.getContext();
        String searchBase = this.realmConfig.getUserStoreProperty("UserSearchBase");
        String searchFilter = this.realmConfig.getUserStoreProperty("UserNameSearchFilter");
        searchFilter = searchFilter.replace("?", this.escapeSpecialCharactersForFilter(userName));
        SearchControls searchControl = new SearchControls();
        String[] returningAttributes = new String[]{"CN"};
        searchControl.setReturningAttributes(returningAttributes);
        searchControl.setSearchScope(2);
        DirContext subDirContext = null;
        NamingEnumeration searchResults = null;

        try {
            searchResults = dirContext.search(this.escapeDNForSearch(searchBase), searchFilter, searchControl);
            SearchResult user = null;

            for (int count = 0; searchResults.hasMore(); ++count) {
                if (count > 0) {
                    throw new UserStoreException("There are more than one result in the user store for user: " + userName);
                }

                user = (SearchResult) searchResults.next();
            }

            if (user == null) {
                throw new UserStoreException("User :" + userName + " does not Exist");
            }

            Secret credentialObj;
            try {
                credentialObj = Secret.getSecret(newCredential);
            } catch (UnsupportedSecretTypeException var26) {
                throw new UserStoreException("Unsupported credential type", var26);
            }

            String[] specialWords = this.realmConfig.getUserStoreProperty("specialWords").split((","));
            log.info("Loading Special Words");

            if (Arrays.asList(specialWords).contains(String.valueOf(credentialObj.getChars()))) {
                log.info("Special Word Detected");
//                return false;
                throw new UserStoreException("Special Words detected in the password");
            }

            log.info("Loading User Attributes");
            String[] properties = {"sn", "givenName"};
            Map<String, String> userProperties = getUserPropertyValues(userName, properties, "default"); //More than one profile
//                log.info(userProperties.get("sn"));


            for (String prop : properties) {
                usrAttrValues.add(userProperties.get(prop));
            }

            if (usrAttrValues.contains(String.valueOf(credentialObj.getChars()))) {
                log.info("Password contains user attribute values");
//                    handleUpdateCredentialFailure("301", "Password contains user attribute values", String.valueOf(credentialObj.getChars()))
//                    return false;
                throw new UserStoreException("Password contains user attribute values");
            }

            log.info("Loading Regular Expressions");
//                String regularExpression = this.realmConfig.getUserStoreProperty("PasswordJavaRegEx");
            String regularCapitalExpression = this.realmConfig.getUserStoreProperty("PasswordCapitalJavaRegEx");
            String regularSimpleExpression = this.realmConfig.getUserStoreProperty("PasswordSimpleJavaRegEx");
            String regularNumberExpression = this.realmConfig.getUserStoreProperty("PasswordNumbersJavaRegEx");
            String regularSpecialCharExpression = this.realmConfig.getUserStoreProperty("PasswordSpecialCharJavaRegEx");
//                var4 = regularExpression == null || this.isFormatCorrect(regularExpression, credentialObj.getChars());

            regMatchCapital = regularCapitalExpression == null || this.isFormatCorrect(regularCapitalExpression, credentialObj.getChars());
            regMatchSimple = regularSimpleExpression == null || this.isFormatCorrect(regularSimpleExpression, credentialObj.getChars());
            regMatchNumber = regularNumberExpression == null || this.isFormatCorrect(regularNumberExpression, credentialObj.getChars());
            regMatchSpecialChar = regularSpecialCharExpression == null || this.isFormatCorrect(regularSpecialCharExpression, credentialObj.getChars());

            log.info("Capital Check: " + regMatchCapital);
            log.info("Simple Check: " + regMatchSimple);
            log.info("Number Check: " + regMatchNumber);
            log.info("Special: " + regMatchSpecialChar);

            regExValidationCount.add(regMatchCapital);
            regExValidationCount.add(regMatchSimple);
            regExValidationCount.add(regMatchNumber);
            regExValidationCount.add(regMatchSpecialChar);

            for (boolean validity : regExValidationCount) {
                if (validity) validityCount++;
            }

            if (validityCount < 3) {
                log.info("Regular Expression check failed");
//                    return false;
                throw new UserStoreException("Password doesn't meet the expected criteria");
            }

            log.info("Regular Expression check passsed");


            if (newCredential != null) {
//                credentialObj;
                try {
                    credentialObj = Secret.getSecret(newCredential);
                } catch (UnsupportedSecretTypeException var26) {
                    throw new UserStoreException("Unsupported credential type", var26);
                }

                try {
                    ModificationItem[] mods = new ModificationItem[]{new ModificationItem(2, new BasicAttribute("unicodePwd", this.createUnicodePassword(credentialObj)))};
                    subDirContext = (DirContext) dirContext.lookup(searchBase);
                    subDirContext.modifyAttributes(user.getName(), mods);
                } finally {
                    credentialObj.clear();
                }
            }
        } catch (NamingException var27) {
            String error = "Can not access the directory service for user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(error, var27);
            }

            throw new UserStoreException(error, var27);
        } finally {
            JNDIUtil.closeNamingEnumeration(searchResults);
            JNDIUtil.closeContext(subDirContext);
            JNDIUtil.closeContext(dirContext);
        }

    }

    private byte[] createUnicodePassword(Secret password) {
        char[] passwordChars = password.getChars();
        char[] quotedPasswordChars = new char[passwordChars.length + 2];

        for (int i = 0; i < quotedPasswordChars.length; ++i) {
            if (i != 0 && i != quotedPasswordChars.length - 1) {
                quotedPasswordChars[i] = passwordChars[i - 1];
            } else {
                quotedPasswordChars[i] = '"';
            }
        }

        password.setChars(quotedPasswordChars);
        return password.getBytes(StandardCharsets.UTF_16LE);
    }

    private String escapeSpecialCharactersForFilter(String dnPartial) {
        boolean replaceEscapeCharacters = true;
        String replaceEscapeCharactersAtUserLoginString = this.realmConfig.getUserStoreProperty("ReplaceEscapeCharactersAtUserLogin");
        if (replaceEscapeCharactersAtUserLoginString != null) {
            replaceEscapeCharacters = Boolean.parseBoolean(replaceEscapeCharactersAtUserLoginString);
            if (log.isDebugEnabled()) {
                log.debug("Replace escape characters configured to: " + replaceEscapeCharactersAtUserLoginString);
            }
        }

        if (replaceEscapeCharacters) {
            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < dnPartial.length(); ++i) {
                char currentChar = dnPartial.charAt(i);
                switch (currentChar) {
                    case '\u0000':
                        sb.append("\\00");
                        break;
                    case '(':
                        sb.append("\\28");
                        break;
                    case ')':
                        sb.append("\\29");
                        break;
                    case '\\':
                        sb.append("\\5c");
                        break;
                    default:
                        sb.append(currentChar);
                }
            }

            return sb.toString();
        } else {
            return dnPartial;
        }
    }

    private String escapeDNForSearch(String dn) {
        boolean replaceEscapeCharacters = true;
        String replaceEscapeCharactersAtUserLoginString = this.realmConfig.getUserStoreProperty("ReplaceEscapeCharactersAtUserLogin");
        if (replaceEscapeCharactersAtUserLoginString != null) {
            replaceEscapeCharacters = Boolean.parseBoolean(replaceEscapeCharactersAtUserLoginString);
            if (log.isDebugEnabled()) {
                log.debug("Replace escape characters configured to: " + replaceEscapeCharactersAtUserLoginString);
            }
        }

        return replaceEscapeCharacters ? dn.replace("\\\\", "\\\\\\").replace("\\\"", "\\\\\"") : dn;
    }

}