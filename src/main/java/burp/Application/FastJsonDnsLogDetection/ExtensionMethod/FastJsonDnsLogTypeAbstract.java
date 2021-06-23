package burp.Application.FastJsonDnsLogDetection.ExtensionMethod;

import burp.IHttpRequestResponse;

/**
 * FastJsonDnsLog扩展的抽象类
 * 所有的FastJsonDnsLog检测的方法都要继承它并实现所有的接口
 */
abstract class FastJsonDnsLogTypeAbstract implements FastJsonDnsLogTypeInterface {
    private String extensionName = "";

    private Boolean isRunExtension = false;

    private Boolean isFastJson = false;

    private String requestIssueName = "";
    private String requestIssueValue = "";

    private IHttpRequestResponse newHttpRequestResponse;

    /**
     * 设置扩展名称 (必须的)
     * @param value
     */
    protected void setExtensionName(String value) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("FastJsonDnsLog扫描扩展-扩展名称不能为空");
        }
        this.extensionName = value;
    }

    /**
     * 扩展名称检查
     * 作用: 让所有不设置扩展名称的扩展无法正常使用, 防止直接调用本类的其他方法, 保证扩展的正常
     */
    private void extensionNameCheck() {
        if (this.extensionName == null || this.extensionName.isEmpty()) {
            throw new IllegalArgumentException("请为该FastJsonDnsLog扫描扩展-设置扩展名称");
        }
    }

    /**
     * 获取扩展名称
     * @return String
     */
    @Override
    public String getExtensionName() {
        this.extensionNameCheck();
        return this.extensionName;
    }

    /**
     * 注册插件 (必须的)
     * 扩展在运行之前必须调用该接口注册, 否则将无法调用本类的其他方法
     */
    protected void registerExtension() {
        this.extensionNameCheck();
        this.isRunExtension = true;
    }

    /**
     * 注册扩展检查
     * 作用: 让所有未调用方法 registerExtension() 的接口, 无法使用本类的其他方法, 保证扩展的正常
     */
    private void registerExtensionCheck() {
        if (!this.isRunExtension) {
            throw new IllegalArgumentException("注意: 该模块未注册,无法使用");
        }
    }

    /**
     * 是否运行扩展
     * true  运行
     * false 不运行
     * @return Boolean
     */
    @Override
    public Boolean isRunExtension() {
        return this.isRunExtension;
    }

    /**
     * 设置为FastJson
     */
    protected void setFastJson() {
        this.registerExtensionCheck();
        this.isFastJson = true;
    }

    /**
     * 是否FastJson框架
     * @return Boolean
     */
    @Override
    public Boolean isFastJson() {
        this.registerExtensionCheck();
        return this.isFastJson;
    }

    /**
     * 设置请求问题参数名称
     * @param value
     */
    protected void setRequestIssueName(String value) {
        this.registerExtensionCheck();
        this.requestIssueName = value;
    }

    /**
     * 获取请求问题参数名称
     * @return String
     */
    @Override
    public String getRequestIssueName() {
        this.registerExtensionCheck();
        return this.requestIssueName;
    }

    /**
     * 设置请求问题参数内容
     * @param value
     */
    protected void setRequestIssueValue(String value) {
        this.registerExtensionCheck();
        this.requestIssueValue = value;
    }

    /**
     * 获取请求问题参数内容
     * @return String
     */
    @Override
    public String getRequestIssueValue() {
        this.registerExtensionCheck();
        return this.requestIssueValue;
    }

    /**
     * 设置http请求与响应对象
     * @param httpRequestResponse
     */
    protected void setHttpRequestResponse(IHttpRequestResponse httpRequestResponse) {
        this.registerExtensionCheck();
        this.newHttpRequestResponse = httpRequestResponse;
    }

    /**
     * 获取http请求与响应对象
     * @return IHttpRequestResponse
     */
    @Override
    public IHttpRequestResponse getHttpRequestResponse() {
        this.registerExtensionCheck();
        return this.newHttpRequestResponse;
    }
}