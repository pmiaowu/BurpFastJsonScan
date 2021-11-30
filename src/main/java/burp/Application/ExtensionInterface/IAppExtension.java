package burp.Application.ExtensionInterface;

import burp.IHttpRequestResponse;
import burp.IScanIssue;

/**
 * Application扩展程序的公共接口
 * 所有Application扩展的抽象类都要继承它并实现所有的接口,才能正常运行
 */
public interface IAppExtension {
    /**
     * 获取-扩展名称
     *
     * @return
     */
    String getExtensionName();

    /**
     * 是否注册了该扩展
     *
     * @return
     */
    Boolean isRegister();

    /**
     * 是否有问题
     *
     * @return
     */
    Boolean isIssue();

    /**
     * 获得-http请求响应
     *
     * @return
     */
    IHttpRequestResponse getHttpRequestResponse();

    /**
     * burp问题详情输出
     *
     * @return
     */
    IScanIssue export();

    /**
     * 控制台输出
     */
    void consoleExport();
}
