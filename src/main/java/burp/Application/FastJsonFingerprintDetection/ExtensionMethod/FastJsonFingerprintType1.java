package burp.Application.FastJsonFingerprintDetection.ExtensionMethod;

import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;

import burp.*;
import burp.Bootstrap.BurpAnalyzedRequest;
import burp.CustomErrorException.TaskTimeoutException;

import burp.DnsLogModule.DnsLog;
import burp.Bootstrap.CustomHelpers;

public class FastJsonFingerprintType1 extends FastJsonFingerprintTypeAbstract {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private CustomHelpers customHelpers;

    private BurpAnalyzedRequest baseAnalyzedRequest;

    private Date startDate;
    private int maxExecutionTime;

    private String[] payloads;

    private DnsLog dnsLog;

    private String sendDnsLogUrl;

    private ArrayList<String> dnsLogUrlArrayList = new ArrayList<String>();
    private ArrayList<IHttpRequestResponse> httpRequestResponseArrayList = new ArrayList<IHttpRequestResponse>();

    public FastJsonFingerprintType1(
            IBurpExtenderCallbacks callbacks,
            BurpAnalyzedRequest baseAnalyzedRequest,
            String[] payloads,
            Date startDate,
            int maxExecutionTime) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.customHelpers = new CustomHelpers();

        this.baseAnalyzedRequest = baseAnalyzedRequest;

        this.dnsLog = new DnsLog(this.callbacks, "DnsLogCn");

        this.payloads = payloads;

        this.startDate = startDate;
        this.maxExecutionTime = maxExecutionTime;

        this.setExtensionName("FastJsonFingerprintType1");
        this.registerExtension();

        this.runExtension();
    }

    private void runExtension() {
        if (this.payloads == null || this.payloads.length <= 0) {
            throw new IllegalArgumentException("FastJson指纹识别扩展-要进行检测的payload不能为空, 请检查");
        }

        // FastJson指纹识别
        for (String payload : this.payloads) {
            // 说明接收到了dnslog请求确定是FastJson
            if (this.isFastJsonFingerprint()) {
                return;
            }

            // 如果dnslog有内容但是 this.isFastJsonFingerprint() 为false
            // 这可能是因为 请求发出去了 dnslog还没反应过来
            // 这种情况后面的循环就没必要了, 退出该循环
            // 等待二次验证即可
            if (this.dnsLog.run().getBodyContent() != null) {
                if (this.dnsLog.run().getBodyContent().length() >= 1) {
                    break;
                }
            }

            // 判断程序是否运行超时
            int startTime = this.customHelpers.getSecondTimestamp(this.startDate);
            int currentTime = this.customHelpers.getSecondTimestamp(new Date());
            int runTime = currentTime - startTime;
            if (runTime >= this.maxExecutionTime) {
                throw new TaskTimeoutException("fastjson fingerprint scan task timeout");
            }

            this.fastJsonFingerprintDetection(payload);
        }

        // 防止因为dnslog卡导致没有检测到的问题, 这里进行二次检测, 保证不会漏报
        // 睡眠一段时间, 给dnslog一个缓冲时间
        try {
            Thread.sleep(6000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        // 开始进行二次验证
        String dnsLogBodyContent = this.dnsLog.run().getBodyContent();
        if (dnsLogBodyContent == null || dnsLogBodyContent.length() <= 0) {
            return;
        }

        // 这里进行二次判断
        for (int i = 0; i < dnsLogUrlArrayList.size(); i++) {
            // dnslog 内容匹配判断
            if (!dnsLogBodyContent.contains(dnsLogUrlArrayList.get(i))) {
                if ((i + 1) != dnsLogUrlArrayList.size()) {
                    continue;
                } else {
                    return;
                }
            }

            // 设置问题详情
            this.setIssuesDetail(httpRequestResponseArrayList.get(i), dnsLogUrlArrayList.get(i));
            return;
        }
    }

    /**
     * 指纹检测
     */
    private void fastJsonFingerprintDetection(String payload) {
        String dnsLogUrl = this.customHelpers.randomStr(8) + "." + this.dnsLog.run().getTemporaryDomainName();

        // 发送请求
        IHttpRequestResponse newHttpRequestResponse = this.makeHttpRequest(payload, dnsLogUrl);

        // 相关变量设置
        this.dnsLogUrlArrayList.add(dnsLogUrl);
        this.httpRequestResponseArrayList.add(newHttpRequestResponse);

        // dnslog 返回的内容判断
        String dnsLogBodyContent = this.dnsLog.run().getBodyContent();
        if (dnsLogBodyContent == null || dnsLogBodyContent.length() <= 0) {
            return;
        }

        // dnslog 内容匹配判断
        if (!dnsLogBodyContent.contains(dnsLogUrl)) {
            return;
        }

        // 设置问题详情
        this.setIssuesDetail(newHttpRequestResponse, dnsLogUrl);
    }

    /**
     * 会根据程序类型自动组装请求的 请求发送接口
     */
    private IHttpRequestResponse makeHttpRequest(String payload, String dnsLogUrl) {
        IHttpService httpService = this.baseAnalyzedRequest.requestResponse().getHttpService();

        if (this.baseAnalyzedRequest.analyzeRequest().getContentType() == 4) {
            // POST请求包提交的数据为json时的处理
            byte[] newParameter = this.buildHttpMessage(payload, dnsLogUrl);
            IHttpRequestResponse newHttpRequestResponse = this.callbacks.makeHttpRequest(httpService, newParameter);
            return newHttpRequestResponse;
        } else {
            // 普通数据格式的处理
            byte[] newParameter = this.buildParameter(payload, dnsLogUrl);
            IHttpRequestResponse newHttpRequestResponse = this.callbacks.makeHttpRequest(httpService, newParameter);
            return newHttpRequestResponse;
        }
    }

    /**
     * json数据格式请求处理方法
     *
     * @param payload
     * @param dnsLogUrl
     * @return
     */
    private byte[] buildHttpMessage(String payload, String dnsLogUrl) {
        String sendData = payload.replace("dnslog-url", ("" + this.customHelpers.randomStr(2) + "." + dnsLogUrl));

        byte[] newParameter = this.helpers.buildHttpMessage(
                this.baseAnalyzedRequest.analyzeRequest().getHeaders(),
                this.helpers.stringToBytes(sendData));
        return newParameter;
    }

    /**
     * 普通数据格式的参数构造方法
     *
     * @param payload
     * @param dnsLogUrl
     * @return
     */
    private byte[] buildParameter(String payload, String dnsLogUrl) {
        byte[] newRequest = this.baseAnalyzedRequest.requestResponse().getRequest();
        for (int i = 0; i < this.baseAnalyzedRequest.getAllJsonParameters().size(); i++) {
            IParameter p = this.baseAnalyzedRequest.getAllJsonParameters().get(i);
            String sendData = payload.replace("dnslog-url", ("" + (i + 1) + "." + dnsLogUrl));
            IParameter newParameter = this.helpers.buildParameter(
                    p.getName(),
                    sendData,
                    p.getType()
            );

            newRequest = this.helpers.updateParameter(
                    newRequest,
                    newParameter);
        }
        return newRequest;
    }

    /**
     * 设置问题详情
     */
    private void setIssuesDetail(IHttpRequestResponse httpRequestResponse, String dnsLogUrl) {
        this.setFastJsonFingerprint();
        this.setHttpRequestResponse(httpRequestResponse);

        this.sendDnsLogUrl = dnsLogUrl;
    }

    @Override
    public IScanIssue export() {
        if (!this.isFastJsonFingerprint()) {
            return null;
        }

        IHttpRequestResponse newHttpRequestResponse = this.getHttpRequestResponse();
        URL newHttpRequestUrl = this.helpers.analyzeRequest(newHttpRequestResponse).getUrl();

        String str1 = String.format("<br/>=============FastJsonFingerprintType1============<br/>");
        String str2 = String.format("ExtensionMethod: %s <br/>", this.getExtensionName());
        String str3 = String.format("sendDnsLogUrl: %s <br/>", this.sendDnsLogUrl);
        String str4 = String.format("=====================================<br/>");

        // dnslog 详情输出
        String str5 = this.dnsLog.run().export();

        // dnslog body内容输出
        String str6 = String.format("<br/>=============DnsLogBodyContent============<br/>");
        String str7 = this.dnsLog.run().getBodyContent();
        String str8 = String.format("<br/>=====================================<br/>");

        String detail = str1 + str2 + str3 + str4 + str5 + str6 + str7 + str8;

        return new CustomScanIssue(
                newHttpRequestResponse.getHttpService(),
                newHttpRequestUrl,
                new IHttpRequestResponse[] { newHttpRequestResponse },
                "FastJson",
                detail,
                "High");
    }

    @Override
    public void consoleExport() {
        if (!this.isFastJsonFingerprint()) {
            return;
        }

        IHttpRequestResponse newHttpRequestResponse = this.getHttpRequestResponse();
        URL newHttpRequestUrl = this.helpers.analyzeRequest(newHttpRequestResponse).getUrl();
        String newHttpRequestMethod = this.helpers.analyzeRequest(newHttpRequestResponse.getRequest()).getMethod();
        int newHttpResponseStatusCode = this.helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode();

        PrintWriter stdout = new PrintWriter(this.callbacks.getStdout(), true);

        stdout.println("");
        stdout.println("===========FastJson指纹详情============");
        stdout.println("你好呀~ (≧ω≦*)喵~");
        stdout.println("这边检测到有一个站点使用了 FastJson并且dns出网 喵~");
        stdout.println(String.format("负责检测的插件: %s", this.getExtensionName()));
        stdout.println(String.format("url: %s", newHttpRequestUrl));
        stdout.println(String.format("请求方法: %s", newHttpRequestMethod));
        stdout.println(String.format("页面http状态: %d", newHttpResponseStatusCode));
        stdout.println(String.format("发送的dnsLogUrl: %s", this.sendDnsLogUrl));
        stdout.println("详情请查看-Burp Scanner模块-Issue activity界面");
        stdout.println("===================================");
        stdout.println("");

        stdout.println("");
        stdout.println("===========DnsLog正文内容============");
        stdout.println(this.dnsLog.run().getBodyContent());
        stdout.println("===================================");
        stdout.println("");
        // dnslog 控制台详情输出
        this.dnsLog.run().consoleExport();
    }
}
