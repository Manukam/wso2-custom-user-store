package com.wso2.carbon.custom.user.store.manager;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.ldap.ActiveDirectoryUserStoreManager;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;
import org.wso2.carbon.user.core.util.JNDIUtil;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.Secret;
import org.wso2.carbon.utils.UnsupportedSecretTypeException;

import javax.naming.Name;
import javax.naming.NameParser;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
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

    @Override
    public void doUpdateCredentialByAdmin(String userName, Object newCredential) throws UserStoreException {
        log.info("Custom update policy");
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

            this.customPasswordValidityChecks(newCredential, userName); //Custom Password Validation Policy

            try {
                this.validatePasswordLastUpdate(dirContext, userName); //24hr Password policy
            } catch (NamingException e) {
                e.printStackTrace();
                log.info("Exception Naming");
            }

            try {
                ModificationItem[] mods = new ModificationItem[]{new ModificationItem(2, new BasicAttribute("unicodePwd", this.createUnicodePassword(credentialObj)))};
                subDirContext = (DirContext) dirContext.lookup(searchBase);
                subDirContext.modifyAttributes(user.getName(), mods);
                log.info("Password updated");
            } finally {
                credentialObj.clear();
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

    public long convertAdTime(String lastChanged){
        return (Long.parseLong(lastChanged) / 10000L) - + 11644473600000L;
    }

    @Override
    public void doAddUser(String userName, Object credential, String[] roleList, Map<String, String> claims, String profileName, boolean requirePasswordChange) throws UserStoreException {
        DirContext dirContext = this.getSearchBaseDirectoryContext();
        BasicAttributes basicAttributes = this.getAddUserBasicAttributes(userName);
        BasicAttribute userPassword = new BasicAttribute("userPassword");
        String passwordHashMethod = this.realmConfig.getUserStoreProperty("PasswordHashMethod");
        if (passwordHashMethod == null) {
            passwordHashMethod = this.realmConfig.getUserStoreProperty("passwordHashMethod");
        }

        Secret credentialObj;
        Object newCredential = credential;
        try {
            credentialObj = Secret.getSecret(newCredential);
        } catch (UnsupportedSecretTypeException var26) {
            throw new UserStoreException("Unsupported credential type", var26);
        }

        this.customPasswordValidityChecks(credential, userName); //Custom Validation Rules.


        byte[] passwordToStore = UserCoreUtil.getPasswordToStore(credential, this.realmConfig.getUserStoreProperty("PasswordHashMethod"), this.kdcEnabled);
        userPassword.add(passwordToStore);
        basicAttributes.put(userPassword);
        this.setUserClaims(claims, basicAttributes, userName);

        String errorMessage;
        try {
            NameParser ldapParser = dirContext.getNameParser("");
            Name compoundName = ldapParser.parse(this.realmConfig.getUserStoreProperty("UserNameAttribute") + "=" + this.escapeSpecialCharactersForDN(userName));
            if (log.isDebugEnabled()) {
                log.debug("Binding user: " + compoundName);
            }

            dirContext.bind(compoundName, (Object)null, basicAttributes);
        } catch (NamingException var19) {
            errorMessage = "Cannot access the directory context or user already exists in the system for user :" + userName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, var19);
            }

            throw new UserStoreException(errorMessage, var19);
        } finally {
            JNDIUtil.closeContext(dirContext);
            UserCoreUtil.clearSensitiveBytes(passwordToStore);
        }

        if (roleList != null && roleList.length > 0) {
            try {
                this.doUpdateRoleListOfUser(userName, (String[])null, roleList);
                if (log.isDebugEnabled()) {
                    log.debug("Roles are added for user  : " + userName + " successfully.");
                }
            } catch (UserStoreException var18) {
                errorMessage = "User is added. But error while updating role list of user : " + userName;
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, var18);
                }

                throw new UserStoreException(errorMessage, var18);
            }
        }

    }

    private String escapeSpecialCharactersForDN(String text) {
        boolean replaceEscapeCharacters = true;
        String replaceEscapeCharactersAtUserLoginString = this.realmConfig.getUserStoreProperty("ReplaceEscapeCharactersAtUserLogin");
        if (replaceEscapeCharactersAtUserLoginString != null) {
            replaceEscapeCharacters = Boolean.parseBoolean(replaceEscapeCharactersAtUserLoginString);
            if (log.isDebugEnabled()) {
                log.debug("Replace escape characters configured to: " + replaceEscapeCharactersAtUserLoginString);
            }
        }

        if (!replaceEscapeCharacters) {
            return text;
        } else {
            StringBuilder sb = new StringBuilder();
            if (text.length() > 0 && (text.charAt(0) == ' ' || text.charAt(0) == '#')) {
                sb.append('\\');
            }

            for(int i = 0; i < text.length(); ++i) {
                char currentChar = text.charAt(i);
                switch(currentChar) {
                    case '"':
                        sb.append("\\\"");
                        break;
                    case '+':
                        sb.append("\\+");
                        break;
                    case ',':
                        sb.append("\\,");
                        break;
                    case ';':
                        sb.append("\\;");
                        break;
                    case '<':
                        sb.append("\\<");
                        break;
                    case '>':
                        sb.append("\\>");
                        break;
                    case '\\':
                        sb.append("\\\\");
                        break;
                    default:
                        sb.append(currentChar);
                }
            }

            if (text.length() > 1 && text.charAt(text.length() - 1) == ' ') {
                sb.insert(sb.length() - 1, '\\');
            }

            if (log.isDebugEnabled()) {
                log.debug("value after escaping special characters in " + text + " : " + sb.toString());
            }

            return sb.toString();
        }
    }

    @Override
    public void doUpdateCredential(String userName, Object newCredential, Object oldCredential) throws UserStoreException{
        DirContext dirContext = this.connectionSource.getContext();
        DirContext subDirContext = null;
        String searchBase = this.realmConfig.getUserStoreProperty("UserSearchBase");
        String searchFilter = this.realmConfig.getUserStoreProperty("UserNameSearchFilter");
        searchFilter = searchFilter.replace("?", this.escapeSpecialCharactersForFilter(userName));
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(2);
        searchControls.setReturningAttributes(new String[]{"userPassword"});
        NamingEnumeration<SearchResult> namingEnumeration = null;
        Object passwords = null;

        this.customPasswordValidityChecks(newCredential, userName); //Custom validation rules
        try {
            this.validatePasswordLastUpdate(dirContext, userName); //24hr Password change policy
        } catch (NamingException e) {
            e.printStackTrace();
            log.info("Exception Naming");
        }

        try {
            String passwordHashMethod;
            try {
                namingEnumeration = dirContext.search(this.escapeDNForSearch(searchBase), searchFilter, searchControls);
                SearchResult searchResult = null;
                passwordHashMethod = this.realmConfig.getUserStoreProperty("PasswordHashMethod");
                if (passwordHashMethod == null) {
                    passwordHashMethod = this.realmConfig.getUserStoreProperty("passwordHashMethod");
                }

                while(namingEnumeration.hasMore()) {
                    searchResult = (SearchResult)namingEnumeration.next();
                    String dnName = searchResult.getName();
                    subDirContext = (DirContext)dirContext.lookup(searchBase);
                    byte[] passwordToStore = UserCoreUtil.getPasswordToStore(newCredential, passwordHashMethod, this.kdcEnabled);

                    try {
                        Attribute passwordAttribute = new BasicAttribute("userPassword");
                        passwordAttribute.add(passwordToStore);
                        BasicAttributes basicAttributes = new BasicAttributes(true);
                        basicAttributes.put(passwordAttribute);
                        subDirContext.modifyAttributes(dnName, 2, basicAttributes);
                    } finally {
                        UserCoreUtil.clearSensitiveBytes(passwordToStore);
                    }
                }

                if (searchResult.getNameInNamespace().equals(this.realmConfig.getUserStoreProperty("ConnectionName"))) {
                    this.connectionSource.updateCredential(newCredential);
                }
            } catch (NamingException var26) {
                passwordHashMethod = "Can not access the directory service for user : " + userName;
                if (log.isDebugEnabled()) {
                    log.debug(passwordHashMethod, var26);
                }

                throw new UserStoreException(passwordHashMethod, var26);
            }
        } finally {
            JNDIUtil.closeNamingEnumeration((NamingEnumeration)passwords);
            JNDIUtil.closeNamingEnumeration(namingEnumeration);
            JNDIUtil.closeContext(subDirContext);
            JNDIUtil.closeContext(dirContext);
        }

    }

    public void customPasswordValidityChecks(Object credential, String userName) throws UserStoreException {
        boolean regMatchCapital;
        boolean regMatchSimple;
        boolean regMatchNumber;
        boolean regMatchSpecialChar;

        ArrayList usrAttrValues = new ArrayList();
        int validityCount = 0;
        ArrayList<Boolean> regExValidationCount = new ArrayList();

        Secret credentialObj;
        try {
            credentialObj = Secret.getSecret(credential);
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


        for (String prop : properties) {
            usrAttrValues.add(userProperties.get(prop));
        }

        if (usrAttrValues.contains(String.valueOf(credentialObj.getChars()))) {
            log.info("Password contains user attribute values");
            throw new UserStoreException("Password contains user attribute values");
        }

        log.info("Loading Regular Expressions");
        String regularCapitalExpression = this.realmConfig.getUserStoreProperty("PasswordCapitalJavaRegEx");
        String regularSimpleExpression = this.realmConfig.getUserStoreProperty("PasswordSimpleJavaRegEx");
        String regularNumberExpression = this.realmConfig.getUserStoreProperty("PasswordNumbersJavaRegEx");
        String regularSpecialCharExpression = this.realmConfig.getUserStoreProperty("PasswordSpecialCharJavaRegEx");

        regMatchCapital = regularCapitalExpression == null || this.isFormatCorrect(regularCapitalExpression, credentialObj.getChars());
        regMatchSimple = regularSimpleExpression == null || this.isFormatCorrect(regularSimpleExpression, credentialObj.getChars());
        regMatchNumber = regularNumberExpression == null || this.isFormatCorrect(regularNumberExpression, credentialObj.getChars());
        regMatchSpecialChar = regularSpecialCharExpression == null || this.isFormatCorrect(regularSpecialCharExpression, credentialObj.getChars());

//        log.info("Capital Check: " + regMatchCapital);
//        log.info("Simple Check: " + regMatchSimple);
//        log.info("Number Check: " + regMatchNumber);
//        log.info("Special: " + regMatchSpecialChar);

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

        log.info("Regular Expression check passed");
    }

    public void validatePasswordLastUpdate(DirContext dirContext, String userName ) throws UserStoreException, NamingException {
        String searchFilter = this.realmConfig.getUserStoreProperty("UserNameSearchFilter");
        String searchFilterReplaced = searchFilter.replace("?", this.escapeSpecialCharactersForFilter(userName));
        String serviceNameAttribute = "pwdLastSet";
        dirContext = this.connectionSource.getContext();
        NamingEnumeration<?> answer = null;
        NamingEnumeration<?> attrs = null;
        String[] returnedAttributes = new String[]{serviceNameAttribute};
        try {
            answer = this.searchForUser(searchFilterReplaced, returnedAttributes, dirContext);

            while (answer.hasMoreElements()) {
                SearchResult sr = (SearchResult) answer.next();
                Attributes attributes = sr.getAttributes();

                if (attributes != null) {
                    Attribute attribute = attributes.get(serviceNameAttribute);
                    if (attribute != null) {
                        StringBuffer attrBuffer = new StringBuffer();
                        attrs = attribute.getAll();
                        log.info("Given User Attribute found");
                    } else {
                        log.info("Given Attributes Not found.");
                    }
                } else {
                    log.info("Attributes null");
                }
            }
        } catch (Exception e) {
            log.info("Exception when retrieving user attributes from AD");
        }

        String lastChanged = attrs.next().toString();
        long adTime = convertAdTime(lastChanged);
        Date changedTime = new Date(adTime);
        GregorianCalendar gc = new GregorianCalendar();
        gc.add(10, -24);
        Date date = gc.getTime();
        if (!changedTime.before((date))) {
            log.info("Can not change password twice within 24 hours.");
            throw new UserStoreException("Can not change password twice within 24 hours.");
        }
    }

}