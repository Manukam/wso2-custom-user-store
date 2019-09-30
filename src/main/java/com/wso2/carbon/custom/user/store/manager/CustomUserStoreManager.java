package com.wso2.carbon.custom.user.store.manager;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.ldap.ActiveDirectoryUserStoreManager;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;
import org.wso2.carbon.utils.Secret;
import org.wso2.carbon.utils.UnsupportedSecretTypeException;
import org.wso2.carbon.user.core.UserStoreException;

import java.nio.CharBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CustomUserStoreManager extends ActiveDirectoryUserStoreManager {
    private static Log log = LogFactory.getLog(CustomUserStoreManager.class);

    private final long AD_TIME_TO_UNIX_DIVISION = 10000L;
    private final long AD_TIME_TO_UNIX_ADDITION = 11644473600000L;

    public CustomUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties,
            ClaimManager claimManager, ProfileConfigurationManager profileManager, UserRealm realm, Integer tenantId)
            throws UserStoreException {
        super(realmConfig, properties, claimManager, profileManager, realm, tenantId);

        log.info("CustomUserStoreManager initialized...");
    }

    public CustomUserStoreManager() {
    }

    @Override
    public void doUpdateCredentialByAdmin(String userName, Object newCredential) throws UserStoreException {
        log.debug("Custom update policy");

        validatePasswordLastUpdate(userName); // 24hr Password policy
        userAttributesCheck(userName, newCredential);
        customPasswordValidityChecks(newCredential, userName); // Custom Password Validation Policy
        super.doUpdateCredentialByAdmin(userName, newCredential);

    }

    @Override
    public void doAddUser(String userName, Object credential, String[] roleList, Map<String, String> claims,
            String profileName, boolean requirePasswordChange) throws UserStoreException {
        customPasswordValidityChecks(credential, userName); // Custom Validation Rules.
        super.doAddUser(userName, credential, roleList, claims, profileName, requirePasswordChange);
    }

    @Override
    public void doUpdateCredential(String userName, Object newCredential, Object oldCredential)
            throws UserStoreException {

        validatePasswordLastUpdate(userName); // 24hr Password change policy
        userAttributesCheck(userName, newCredential); //User Attribute Check
        customPasswordValidityChecks(newCredential, userName); // Custom validation rules
        super.doUpdateCredential(userName, newCredential, oldCredential);

    }

    private void customPasswordValidityChecks(Object credential, String userName) throws UserStoreException {

        Secret credentialObj;
        try {
            credentialObj = Secret.getSecret(credential);
        } catch (UnsupportedSecretTypeException e) {
            throw new UserStoreException("Unsupported credential type", e);
        }

        specialWordCheck(credentialObj);
        passwordCriteriaCheck(credentialObj);

    }


    private void validatePasswordLastUpdate(String userName) throws UserStoreException {
        String[] passwordLastUpdateAttribute = {
                this.realmConfig.getUserStoreProperty("PasswordLastUpdatedColumnName") };
        Map<String, String> userProperties = getUserPropertyValues(userName, passwordLastUpdateAttribute, "default");
        if (!userProperties.isEmpty()) {
            String lastChanged = userProperties.get(passwordLastUpdateAttribute[0]);
            long adTime = convertAdTime(lastChanged);
            Date changedTime = new Date(adTime);
            GregorianCalendar gc = new GregorianCalendar();
            gc.add(10, -24);
            Date date = gc.getTime();
            if (!changedTime.before((date))) {
                log.debug("Can not change password twice within 24 hours.");
                throw new UserStoreException("Can not change password twice within 24 hours.");
            }
        } else {
            log.warn("User properties for given column name is not found. Skipping Password Last update validation");
        }
    }

    private void specialWordCheck(Secret credentialObj) throws UserStoreException {
        String specialWordConfig = this.realmConfig.getUserStoreProperty("PasswordSpecialWordsCheck");
        if (specialWordConfig != null) {
            String[] specialWords = specialWordConfig.split((",").trim());
            if (specialWords.length > 0) {
                if (Arrays.asList(specialWords).contains(String.valueOf(credentialObj.getChars()))) {
                    log.debug("Special Word Detected: " + Arrays.toString(specialWords));
                    throw new UserStoreException("Special Words detected in the password");
                }
            }
        } else {
            log.warn("Values for SpecialWord Validation check not configured. Skipping validation");
        }
    }

    private void userAttributesCheck(String userName, Object credential) throws UserStoreException {
        Secret credentialObj;
        try {
            credentialObj = Secret.getSecret(credential);
        } catch (UnsupportedSecretTypeException e) {
            throw new UserStoreException("Unsupported credential type", e);
        }
        ArrayList<String> usrAttrValues = new ArrayList<>();
        log.debug("Loading User Attributes");
        String userAttributesConfig = this.realmConfig.getUserStoreProperty("PasswordUserAttributesCheck");
        if (userAttributesConfig != null) {
            String[] properties = userAttributesConfig.split((",").trim());
            Map<String, String> userProperties = getUserPropertyValues(userName, properties, "default");

            for (String prop : properties) {
                usrAttrValues.add(userProperties.get(prop));
            }
            if (usrAttrValues.contains(String.valueOf(credentialObj.getChars()))) {
                log.debug("Password contains user attribute values");
                throw new UserStoreException("Password contains user attribute values");
            }
        } else {
            log.warn(
                    "Values for user attributes password validation not configured. Skipping user attributes password validation");
        }
    }

    private void passwordCriteriaCheck(Secret credentialObj) throws UserStoreException {
        boolean regMatchCapital;
        boolean regMatchSimple;
        boolean regMatchNumber;
        boolean regMatchSpecialChar;
        int validityCount = 0;
        ArrayList<Boolean> regExValidationCount = new ArrayList<>();
        log.debug("Loading Regular Expressions");

        String regularCapitalExpression = this.realmConfig.getUserStoreProperty("PasswordCapitalJavaRegEx");
        String regularNumberExpression = this.realmConfig.getUserStoreProperty("PasswordNumbersJavaRegEx");
        String regularSimpleExpression = this.realmConfig.getUserStoreProperty("PasswordSimpleJavaRegEx");
        String regularSpecialCharExpression = this.realmConfig.getUserStoreProperty("PasswordSpecialCharJavaRegEx");

        regMatchCapital = regularCapitalExpression == null
                || this.isFormatCorrect(regularCapitalExpression, credentialObj.getChars());
        regMatchSimple = regularSimpleExpression == null
                || this.isFormatCorrect(regularSimpleExpression, credentialObj.getChars());
        regMatchNumber = regularNumberExpression == null
                || this.isFormatCorrect(regularNumberExpression, credentialObj.getChars());
        regMatchSpecialChar = regularSpecialCharExpression == null
                || this.isFormatCorrect(regularSpecialCharExpression, credentialObj.getChars());

        regExValidationCount.add(regMatchCapital);
        regExValidationCount.add(regMatchSimple);
        regExValidationCount.add(regMatchNumber);
        regExValidationCount.add(regMatchSpecialChar);

        for (boolean validity : regExValidationCount) {
            if (validity)
                validityCount++;
        }

        if (validityCount < 3) {
            log.debug("Regular Expression check failed");
            throw new UserStoreException("Password doesn't meet the expected criteria");
        }

        log.debug("Regular Expression check passed");
    }

    private boolean isFormatCorrect(String regularExpression, char[] attribute) {
        CharBuffer charBuffer = CharBuffer.wrap(attribute);
        Pattern p2 = Pattern.compile(regularExpression);
        Matcher m2 = p2.matcher(charBuffer);
        return m2.find();
    }

    private long convertAdTime(String adTimeInMilis) {
        return (Long.parseLong(adTimeInMilis) / AD_TIME_TO_UNIX_DIVISION) - +AD_TIME_TO_UNIX_ADDITION;
    }

}