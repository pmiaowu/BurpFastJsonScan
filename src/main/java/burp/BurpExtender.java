package burp;

import java.net.URL;
import java.util.List;
import java.util.ArrayList;
import java.io.PrintWriter;
import java.net.MalformedURLException;

import burp.Bootstrap.DomainNameRepeat;
import burp.Bootstrap.UrlRepeat;
import burp.Bootstrap.BurpAnalyzedRequest;
import burp.Application.FastJsonDnsLogDetection.FastJsonDnsLog;
import burp.CustomErrorException.TaskTimeoutException;

public class BurpExtender implements IBurpExtender, IScannerCheck {

    public static String NAME = "FastJsonScan";
    public static String VERSION = "1.0.8";

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private Tags tags;

    private DomainNameRepeat domainNameRepeat;
    private UrlRepeat urlRepeat;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        this.domainNameRepeat = new DomainNameRepeat();
        this.urlRepeat = new UrlRepeat();

        // 标签界面
        this.tags = new Tags(callbacks, NAME);

        callbacks.setExtensionName(NAME);
        callbacks.registerScannerCheck(this);

        this.stdout.println("===================================");
        this.stdout.println(String.format("%s 加载成功", NAME));
        this.stdout.println(String.format("版本: %s", VERSION));
        this.stdout.println("作者: P喵呜-PHPoop");
        this.stdout.println("QQ: 3303003493");
        this.stdout.println("微信: a3303003493");
        this.stdout.println("GitHub: https://github.com/pmiaowu");
        this.stdout.println("Blog: https://www.yuque.com/pmiaowu");
        this.stdout.println("===================================");
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<IScanIssue>();

        // 基础请求域名构造
        String baseRequestProtocol = baseRequestResponse.getHttpService().getProtocol();
        String baseRequestHost = baseRequestResponse.getHttpService().getHost();
        int baseRequestPort = baseRequestResponse.getHttpService().getPort();
        String baseRequestPath = this.helpers.analyzeRequest(baseRequestResponse).getUrl().getPath();

        String baseRequestDomainName = baseRequestProtocol + "://" + baseRequestHost + ":" + baseRequestPort;

        URL baseHttpRequestUrl = null;
        try {
            baseHttpRequestUrl = new URL(baseRequestDomainName + "/" + baseRequestPath);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }

        // 判断是否有json，没有就不执行
        BurpAnalyzedRequest baseAnalyzedRequest = new BurpAnalyzedRequest(this.callbacks, baseRequestResponse);

        if (!baseAnalyzedRequest.isRequestParameterContentJson()) {
            return issues;
        }

        // 域名重复检查
        if (this.domainNameRepeat.check(baseRequestDomainName)) {
            return null;
        }

        // url重复检测-模块运行
        IRequestInfo analyzedIResponseInfo = this.helpers.analyzeRequest(baseRequestResponse.getRequest());
        String baseRequestMethod = analyzedIResponseInfo.getMethod();
        String newBaseUrl = this.urlRepeat.RemoveUrlParameterValue(baseHttpRequestUrl.toString());

        // url重复检查
        if (this.urlRepeat.check(baseRequestMethod, newBaseUrl)) {
            return null;
        }

        // 确定以前没有执行过 把该url加入进数组里面防止下次重复扫描
        this.urlRepeat.addMethodAndUrl(baseRequestMethod, newBaseUrl);

        // 添加任务到面板中等待检测
        byte[] baseResponse = baseRequestResponse.getResponse();
        int tagId = this.tags.add(
                "",
                this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                baseHttpRequestUrl.toString(),
                this.helpers.analyzeResponse(baseResponse).getStatusCode() + "",
                "waiting for test results",
                baseRequestResponse
        );

        try {
            // FastJsonDnsLog检测-模块运行
            FastJsonDnsLog fastJsonDnsLog = new FastJsonDnsLog(this.callbacks, baseAnalyzedRequest, "FastJsonDnsLogType1");
            if (fastJsonDnsLog.run().isRunExtension()) {
                // 检测是否使用了FastJson
                if (fastJsonDnsLog.run().isFastJson()) {
                    // 确定使用了FastJson 把该域名加入进HashMap里面防止下次重复扫描
                    this.domainNameRepeat.add(baseRequestDomainName);

                    // FastJsonDnsLog检测-报告输出
                    issues.add(fastJsonDnsLog.run().export());

                    // FastJsonDnsLog检测-控制台报告输出
                    fastJsonDnsLog.run().consoleExport();

                    // 检查出来使用了FastJson-更新任务状态至任务栏面板
                    IHttpRequestResponse fastJsonDnsLogRequestResponse = fastJsonDnsLog.run().getHttpRequestResponse();
                    byte[] fastJsonDnsLogResponse = fastJsonDnsLogRequestResponse.getResponse();
                    this.tags.save(
                            tagId,
                            fastJsonDnsLog.run().getExtensionName(),
                            this.helpers.analyzeRequest(fastJsonDnsLogRequestResponse).getMethod(),
                            baseHttpRequestUrl.toString(),
                            this.helpers.analyzeResponse(fastJsonDnsLogResponse).getStatusCode() + "",
                            "[+] found fastJson",
                            fastJsonDnsLogRequestResponse
                    );
                    return issues;
                }
            }

            // 未检测出来使用了FastJson-更新任务状态至任务栏面板
            this.tags.save(
                    tagId,
                    "ALL",
                    this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                    baseHttpRequestUrl.toString(),
                    this.helpers.analyzeResponse(baseResponse).getStatusCode() + "",
                    "[-] not found fastJson",
                    baseRequestResponse
            );
        } catch (TaskTimeoutException e) {
            this.urlRepeat.delMethodAndUrl(baseRequestMethod, newBaseUrl);
            this.domainNameRepeat.del(baseRequestDomainName);

            // 通知控制台报错
            this.stdout.println("========FastJson插件错误-程序运行超时============");
            this.stdout.println(String.format("url: %s", baseHttpRequestUrl));
            this.stdout.println("请使用该url重新访问,若是还多次出现此错误,则很有可能waf拦截");
            this.stdout.println("========================================");

            // 本次任务执行有问题-更新任务状态至任务栏面板
            this.tags.save(
                    tagId,
                    "",
                    this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                    baseHttpRequestUrl.toString(),
                    this.helpers.analyzeResponse(baseResponse).getStatusCode() + "",
                    "fastJson scan task timeout",
                    baseRequestResponse
            );
        } catch (Exception e) {
            this.urlRepeat.delMethodAndUrl(baseRequestMethod, newBaseUrl);
            this.domainNameRepeat.del(baseRequestDomainName);

            // 通知控制台报错
            this.stdout.println("========FastJson插件错误-未知错误============");
            this.stdout.println(String.format("url: %s", baseHttpRequestUrl));
            this.stdout.println("请使用该url重新访问,若是还多次出现此错误,则很有可能waf拦截");
            this.stdout.println("========================================");

            // 本次任务执行有问题-更新任务状态至任务栏面板
            this.tags.save(
                    tagId,
                    "",
                    this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                    baseHttpRequestUrl.toString(),
                    this.helpers.analyzeResponse(baseResponse).getStatusCode() + "",
                    "fastJson scan unknown error",
                    baseRequestResponse
            );
        } finally {
            this.taskCompletionConsoleExport(baseRequestResponse);

            // 输出跑到的问题给burp
            return issues;
        }
    }

    /**
     * 任务完成情况控制台输出
     */
    private void taskCompletionConsoleExport(IHttpRequestResponse requestResponse) {
        URL httpRequestUrl = this.helpers.analyzeRequest(requestResponse).getUrl();
        this.stdout.println("============FastJson-scan扫描完毕================");
        this.stdout.println(String.format("url: %s", httpRequestUrl));
        this.stdout.println("========================================");
        this.stdout.println(" ");
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
            return -1;
        } else {
            return 0;
        }
    }
}