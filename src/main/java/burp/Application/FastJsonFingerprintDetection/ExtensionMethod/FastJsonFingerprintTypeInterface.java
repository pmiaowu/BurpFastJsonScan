package burp.Application.FastJsonFingerprintDetection.ExtensionMethod;

import burp.IScanIssue;
import burp.IHttpRequestResponse;

/**
 * fastjson指纹扩展的公共接口
 * 所有的抽象类都要继承它并实现所有的接口
 */
public interface FastJsonFingerprintTypeInterface {
    String getExtensionName();

    Boolean isRunExtension();

    Boolean isFastJsonFingerprint();

    String getRequestIssueName();

    String getRequestIssueValue();

    IHttpRequestResponse getHttpRequestResponse();

    IScanIssue export();

    void consoleExport();
}
