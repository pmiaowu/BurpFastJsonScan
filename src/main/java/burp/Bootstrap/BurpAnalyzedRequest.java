package burp.Bootstrap;

import burp.*;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

public class BurpAnalyzedRequest {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private CustomHelpers customHelpers;

    private List<IParameter> jsonParameters = new ArrayList<IParameter>();

    private IHttpRequestResponse requestResponse;

    public BurpAnalyzedRequest(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.customHelpers = new CustomHelpers();

        this.requestResponse = requestResponse;

        this.setJsonParameters();
    }

    public IHttpRequestResponse requestResponse() {
        return this.requestResponse;
    }

    public IRequestInfo analyzeRequest() {
        return this.helpers.analyzeRequest(this.requestResponse);
    }

    /**
     * 请求参数内容是否为json
     *
     * @return
     */
    public boolean isRequestParameterContentJson() {
        if (this.customHelpers.isJson(this.getHttpRequestBody(this.requestResponse()))) {
            return true;
        }

        if (this.getAllJsonParameters().isEmpty()) {
            return false;
        }

        return true;
    }

    /**
     * 获取请求的Body内容
     * @param httpRequestResponse
     * @return String
     */
    private String getHttpRequestBody(IHttpRequestResponse httpRequestResponse) {
        byte[] request = httpRequestResponse.getRequest();
        IRequestInfo requestInfo = this.helpers.analyzeRequest(request);

        int httpBodyOffset = requestInfo.getBodyOffset();
        int httpBodyLength = request.length - httpBodyOffset;

        String httpBody = null;
        try {
            httpBody = new String(request, httpBodyOffset, httpBodyLength, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        return httpBody;
    }

    /**
     * 设置提取所有的json参数
     */
    public void setJsonParameters() {
        byte contentType = this.analyzeRequest().getContentType();

        if (contentType == 4) {
            return;
        }

        for (IParameter p : this.analyzeRequest().getParameters()) {
            if (this.customHelpers.isJson(this.helpers.urlDecode(p.getValue()))) {
                this.jsonParameters.add(p);
            }
        }
    }

    /**
     * 获取所有的json参数
     *
     * @return
     */
    public List<IParameter> getAllJsonParameters() {
        return this.jsonParameters;
    }
}
