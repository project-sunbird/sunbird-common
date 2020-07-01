package org.sunbird.auth.verifier;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.jclouds.openstack.nova.v2_0.domain.Server;
import org.sunbird.common.exception.ProjectCommonException;
import org.sunbird.common.models.util.JsonKey;
import org.sunbird.common.models.util.LoggerEnum;
import org.sunbird.common.models.util.ProjectLogger;
import org.sunbird.common.responsecode.ResponseCode;

import java.util.Map;

public class ManagedTokenValidator {
    
    private static ObjectMapper mapper = new ObjectMapper();
    
    /** managedtoken is validated and requestedByUserID values are validated aganist the managedEncToken
     * @param managedEncToken
     * @param requestedByUserId
     * @return
     */
    public static String verify(String managedEncToken, String requestedByUserId) {
        boolean isValid = false;
        String managedFor = JsonKey.UNAUTHORIZED;
        try {
            String[] tokenElements = managedEncToken.split("\\.");
            String header = tokenElements[0];
            String body = tokenElements[1];
            String signature = tokenElements[2];
            String payLoad = header + JsonKey.DOT_SEPARATOR + body;
            Map<Object, Object> headerData = mapper.readValue(new String(decodeFromBase64(header)), Map.class);
            String keyId = headerData.get("kid").toString();
            ProjectLogger.log("ManagedTokenValidator:verify: keyId: " + keyId,
                    LoggerEnum.INFO.name());
            Map<String, String> tokenBody = mapper.readValue(new String(decodeFromBase64(body)), Map.class);
            String parentId = tokenBody.get(JsonKey.PARENT_ID);
            String muaId = tokenBody.get(JsonKey.SUB);
            ProjectLogger.log("ManagedTokenValidator:verify : X-Authenticated-For validation starts.", LoggerEnum.INFO.name());
            isValid = CryptoUtil.verifyRSASign(payLoad, decodeFromBase64(signature), KeyManager.getPublicKey(keyId).getPublicKey(), JsonKey.SHA_256_WITH_RSA);
            ProjectLogger.log("ManagedTokenValidator:verify : X-Authenticated-For validation done and isValid = " + isValid, LoggerEnum.INFO.name());
            isValid &= parentId.equalsIgnoreCase(requestedByUserId);
            ProjectLogger.log("ManagedTokenValidator:verify : ParentId and RequestedBy userId validation done and isValid = " + isValid, LoggerEnum.INFO.name());
            if (isValid) {
                managedFor = muaId;
            }
        } catch (Exception ex) {
            ProjectLogger.log("Exception in ManagedTokenValidator: verify ", LoggerEnum.ERROR);
            ex.printStackTrace();
        }
        return managedFor;
    }

    private static byte[] decodeFromBase64(String data) {
        return Base64Util.decode(data, 11);
    }
    
}