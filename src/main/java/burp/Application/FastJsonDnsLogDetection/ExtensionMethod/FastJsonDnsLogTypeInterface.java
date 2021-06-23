package burp.Application.FastJsonDnsLogDetection.ExtensionMethod;

import burp.IScanIssue;
import burp.IHttpRequestResponse;

/**
 * FastJsonDnsLog扩展的公共接口
 * 所有的抽象类都要继承它并实现所有的接口
 */
public interface FastJsonDnsLogTypeInterface {
    String getExtensionName();

    Boolean isRunExtension();

    Boolean isFastJson();

    String getRequestIssueName();

    String getRequestIssueValue();

    IHttpRequestResponse getHttpRequestResponse();

    IScanIssue export();

    void consoleExport();
}
