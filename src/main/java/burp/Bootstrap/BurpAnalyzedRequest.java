package burp.Bootstrap;

import java.util.List;
import java.util.ArrayList;

import burp.*;
import burp.Ui.Tags;

public class BurpAnalyzedRequest {
    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    private CustomBurpHelpers customBurpHelpers;

    private List<IParameter> jsonParameters = new ArrayList<>();
    private List<IParameter> eligibleJsonParameters = new ArrayList<>();

    private IHttpRequestResponse requestResponse;

    private Tags tags;

    public BurpAnalyzedRequest(IBurpExtenderCallbacks callbacks, Tags tags, IHttpRequestResponse requestResponse) {
        this.callbacks = callbacks;
        this.helpers = this.callbacks.getHelpers();

        this.tags = tags;

        this.customBurpHelpers = new CustomBurpHelpers(callbacks);
        this.requestResponse = requestResponse;

        initJsonParameters();
        initEligibleJsonParameters();
    }

    public IHttpRequestResponse requestResponse() {
        return this.requestResponse;
    }

    public IRequestInfo analyzeRequest() {
        return this.helpers.analyzeRequest(this.requestResponse.getRequest());
    }

    /**
     * 初始化json参数
     */
    private void initJsonParameters() {
        if (analyzeRequest().getParameters().isEmpty()) {
            return;
        }

        for (IParameter p : analyzeRequest().getParameters()) {
            // 为6的时候,表示为json
            // 不是那种 key=json 所以无需加入这里面
            if (p.getType() == 6) {
                continue;
            }
            if (p.getName() == null || "".equals(p.getName())) {
                continue;
            }
            if (CustomHelpers.isJson(this.helpers.urlDecode(p.getValue()))) {
                this.jsonParameters.add(p);
            }
        }
    }

    /**
     * 获取所有的json参数
     *
     * @return List<IParameter>
     */
    public List<IParameter> getAllJsonParameters() {
        return this.jsonParameters;
    }

    /**
     * 初始化所有符合条件的json参数
     */
    private void initEligibleJsonParameters() {
        List<Integer> scanTypeList = this.tags.getBaseSettingTagClass().getScanTypeList();

        if (this.getAllJsonParameters().size() == 0) {
            return;
        }

        for (IParameter p : this.getAllJsonParameters()) {
            for (Integer type : scanTypeList) {
                if (p.getType() == type) {
                    this.eligibleJsonParameters.add(p);
                }
            }
        }
    }

    /**
     * 获取所有符合条件的json参数
     *
     * @return List<IParameter>
     */
    public List<IParameter> getEligibleJsonParameters() {
        return this.eligibleJsonParameters;
    }

    /**
     * 判断请求参数内容是否有Json
     *
     * @return boolean
     */
    public boolean isRequestParameterContentJson() {
        if (CustomHelpers.isJson(this.customBurpHelpers.getHttpRequestBody(requestResponse().getRequest()))) {
            return true;
        }
        if (getAllJsonParameters().isEmpty()) {
            return false;
        }
        return true;
    }

    /**
     * 判断站点是否有符合条件的json
     *
     * @return
     */
    public Boolean isSiteEligibleJson() {
        List<Integer> scanTypeList = this.tags.getBaseSettingTagClass().getScanTypeList();
        if (CustomHelpers.isJson(this.customBurpHelpers.getHttpRequestBody(requestResponse().getRequest()))) {
            for (Integer type : scanTypeList) {
                if (type == 6) {
                    return true;
                }
            }
        }

        if (this.getEligibleJsonParameters().size() > 0) {
            return true;
        }

        return false;
    }

    /**
     * 会根据程序类型自动组装请求的 请求发送接口
     */
    public IHttpRequestResponse makeHttpRequest(String payload, List<String> newHeaders) {
        byte[] newRequest;

        List<String> headers = this.analyzeRequest().getHeaders();
        if (newHeaders != null && newHeaders.size() != 0) {
            headers.addAll(newHeaders);
        }

        if (this.tags.getBaseSettingTagClass().isScanJson() && this.analyzeRequest().getContentType() == 4) {
            // POST请求包提交的数据为json时的处理
            newRequest = this.buildParameter(payload, this.buildHttpMessage(payload), headers);
        } else {
            // 普通数据格式的处理
            newRequest = this.buildParameter(payload, null, headers);
        }

        IHttpRequestResponse newHttpRequestResponse = this.callbacks.makeHttpRequest(this.requestResponse().getHttpService(), newRequest);
        return newHttpRequestResponse;
    }

    /**
     * json数据格式请求处理方法
     *
     * @param payload
     * @return
     */
    private byte[] buildHttpMessage(String payload) {
        byte[] newRequest = this.helpers.buildHttpMessage(
                this.analyzeRequest().getHeaders(),
                this.helpers.stringToBytes(payload));
        return newRequest;
    }

    /**
     * 普通数据格式的参数构造方法
     *
     * @param payload
     * @return
     */
    private byte[] buildParameter(String payload, byte[] request, List<String> headers) {
        byte[] newRequest;

        if (request == null) {
            newRequest = this.requestResponse().getRequest();
        } else {
            newRequest = request;
        }

        // 添加header头
        newRequest = this.helpers.buildHttpMessage(
                headers,
                this.customBurpHelpers.getHttpRequestBody(newRequest).getBytes());

        for (int i = 0; i < this.getEligibleJsonParameters().size(); i++) {
            IParameter p = this.getEligibleJsonParameters().get(i);
            IParameter newParameter = this.helpers.buildParameter(
                    p.getName(),
                    payload,
                    p.getType()
            );

            newRequest = this.helpers.updateParameter(
                    newRequest,
                    newParameter);
        }
        return newRequest;
    }
}