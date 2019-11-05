# wso2-custom-user-store

> A Custom Secondary User Store manager for WSO2 IS 5.7 that uses Active Directory.
> This user store manager has the capability to perform the following custom password validations,
  * Password should contain more than 20 characters. (Configurable)
  * Password should comply with 3 of the following to be deemed valid. (Configurable)
    * Contain Capital letters [A-Z]
    * Contain Simple letters [a-z]
    * Contain numbers [0-9]
    * Contain a special character [$,_,-,.]
   
  * Can not change the password twice within 24 hours.
  * Can not contain pre-defined special words (Configurable)
  * Can not contain user attributes, such as first name, last name of user. (Configurable)

## Build Setup

* Navigate to the project root directory and execute the following.
``` bash
  mvn clean install
```
* Navigate to the `/target` folder in the project directory and copy and paste the `com.wso2.carbon.custom.user.store.manager-1.3.0.jar` to `IS_HOME/repository/components/dropins`

* Start the WSO2 IS server

* Navigate to User Stores -> Add

* Select the `com.wso2.carbon.custom.user.store.manager.CustomUserStoreManager` as the `User Store Manager Class` from the dropdown.

* Give a `unique domain name`

* Fill in the rest of the details as per your configurations and click `Add`

* Navigate to `IS_HOME/repository/deployment/server/userstores` and open the file name with the unique domain name provided in the above steps.

* To configure the special words the password should be validated against, add a new `property` inside the `UserStoreManager` and name it `PasswordSpecialWordsCheck` and define the special words as shown below.

  `<Property name="PasswordSpecialWordsCheck">SpecialWord1,SpecialWord2</Property>`
  
* To configure the attributes of the user the password should be validated against, add a new `property` inside the `UserStoreManager` and name it `PasswordUserAttributesCheck` and define the attributes as shown below.

  `<Property name="PasswordUserAttributesCheck">sn,givenName </Property>`
  
* To configure the password character length, please edit the `PasswordLengthCheck` property.
 
* Restart the IS server and the test the password validations.
