package burp.Application.ExtensionInterface;

import burp.IHttpRequestResponse;

/**
 * Application扩展的抽象类
 * 所有的 Application扩展 都要继承它并实现所有的接口,才能正常运行
 */
public abstract class AAppExtension implements IAppExtension {
    private String extensionName = "";

    private Boolean isRegister = false;

    private Boolean isIssues = false;

    private IHttpRequestResponse httpRequestResponse;

    /**
     * 设置扩展名称 (必须的)
     *
     * @param name
     */
    protected void setExtensionName(String name) {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("Application-扩展名称不能为空");
        }
        this.extensionName = name;
    }

    /**
     * 获取扩展名称
     *
     * @return String
     */
    @Override
    public String getExtensionName() {
        return this.extensionName;
    }

    /**
     * 注册插件 (必须的)
     * 扩展在运行之前必须调用该接口注册, 否则将无法调用本类的其他方法
     */
    protected void registerExtension() {
        this.isRegister = true;
    }

    /**
     * 是否注册了该扩展
     * true 注册, false 未注册
     * 注: 未注册的扩展禁止执行
     *
     * @return Boolean
     */
    @Override
    public Boolean isRegister() {
        return this.isRegister;
    }

    /**
     * 设置问题状态
     */
    protected void setIssueState(Boolean state) {
        this.isIssues = state;
    }

    /**
     * 是否有问题
     *
     * @return
     */
    @Override
    public Boolean isIssue() {
        return this.isIssues;
    }

    /**
     * 设置http请求与响应对象
     *
     * @param httpRequestResponse
     */
    protected void setHttpRequestResponse(IHttpRequestResponse httpRequestResponse) {
        this.httpRequestResponse = httpRequestResponse;
    }

    /**
     * 获取http请求与响应对象
     *
     * @return IHttpRequestResponse
     */
    @Override
    public IHttpRequestResponse getHttpRequestResponse() {
        return this.httpRequestResponse;
    }
}
