package com.wso2.carbon.custom.user.store.manager.internal;

import com.wso2.carbon.custom.user.store.manager.CustomUserStoreManager;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;


@Component(
        name = "com.wso2.carbon.custom.user.store.manager",
        immediate = true

)
public class CustomUserStoreMgtDSComponent {
    private static Log log = LogFactory.getLog(CustomUserStoreMgtDSComponent.class);
    private static RealmService realmService;

    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            CustomUserStoreManager customUserStoreManager = new CustomUserStoreManager();
            ctxt.getBundleContext().registerService(UserStoreManager.class.getName(), customUserStoreManager, null);
            log.info("CustomUserStoreManager bundle activated successfully..");
        } catch (Throwable storeError) {
            log.error("ERROR when activating Custom User Store", storeError);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.debug("Custom User Store Manager is deactivated ");
        }
    }

    @Reference(
            name = "RealmService",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {
        realmService = realmService;
    }

    protected void unsetRealmService(RealmService realmService) {
        realmService = null;
    }
}
