package burp;

import java.net.URL;
import java.util.List;
import java.util.ArrayList;
import java.io.PrintWriter;

import burp.Bootstrap.DomainNameRepeat;
import burp.Bootstrap.UrlRepeat;
import burp.Bootstrap.BurpAnalyzedRequest;
import burp.Application.FastJsonFingerprintDetection.FastJsonFingerprint;
import burp.CustomErrorException.TaskTimeoutException;

public class BurpExtender implements IBurpExtender, IScannerCheck {

    public static String NAME = "FastJsonScan";
    public static String VERSION = "1.0.0";

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

        URL baseHttpRequestUrl = this.helpers.analyzeRequest(baseRequestResponse).getUrl();

        // 基础请求域名构造
        String baseRequestProtocol = baseRequestResponse.getHttpService().getProtocol();
        String baseRequestHost = baseRequestResponse.getHttpService().getHost();
        int baseRequestPort = baseRequestResponse.getHttpService().getPort();
        String baseRequestDomainName = baseRequestProtocol + "://" + baseRequestHost + ":" + baseRequestPort;

        // 判断对应参数是否为空，为空不执行
        IRequestInfo analyzedRequest = this.helpers.analyzeRequest(baseRequestResponse.getRequest());
        if (analyzedRequest.getParameters().isEmpty()) {
            return issues;
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

        URL baseRequestUrl = this.helpers.analyzeRequest(baseRequestResponse).getUrl();
        String newBaseUrl = this.urlRepeat.RemoveUrlParameterValue(baseRequestUrl.toString());

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
                baseRequestUrl.toString(),
                this.helpers.analyzeResponse(baseResponse).getStatusCode() + "",
                "waiting for test results",
                baseRequestResponse
        );

        try {
            // fastJson指纹检测-模块运行
            FastJsonFingerprint fastJsonFingerprint = new FastJsonFingerprint(this.callbacks, baseAnalyzedRequest, "FastJsonFingerprintType1");
            if (!fastJsonFingerprint.run().isRunExtension()) {
                return null;
            }

            // 检测是否使用了FastJson
            if (!fastJsonFingerprint.run().isFastJsonFingerprint()) {
                // 任务完成情况控制台输出
                this.taskCompletionConsoleExport(baseRequestResponse);

                // 未检测出来使用了FastJson-更新任务状态至任务栏面板
                this.tags.save(
                        tagId,
                        fastJsonFingerprint.run().getExtensionName(),
                        this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                        baseRequestUrl.toString(),
                        this.helpers.analyzeResponse(baseResponse).getStatusCode() + "",
                        "[-] not found fastJson",
                        baseRequestResponse
                );
                return issues;
            }

            // 确定使用了FastJson 把该域名加入进HashMap里面防止下次重复扫描
            this.domainNameRepeat.add(baseRequestDomainName);

            // FastJson指纹检测-报告输出
            issues.add(fastJsonFingerprint.run().export());

            // FastJson指纹检测-控制台报告输出
            fastJsonFingerprint.run().consoleExport();

            // 检查出来使用了FastJson-更新任务状态至任务栏面板
            IHttpRequestResponse fastJsonFingerprintRequestResponse = fastJsonFingerprint.run().getHttpRequestResponse();
            byte[] fastJsonFingerprintResponse = fastJsonFingerprintRequestResponse.getResponse();
            this.tags.save(
                    tagId,
                    fastJsonFingerprint.run().getExtensionName(),
                    this.helpers.analyzeRequest(fastJsonFingerprintRequestResponse).getMethod(),
                    baseRequestUrl.toString(),
                    this.helpers.analyzeResponse(fastJsonFingerprintResponse).getStatusCode() + "",
                    "[+] found fastJson",
                    fastJsonFingerprintRequestResponse
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
                    baseRequestUrl.toString(),
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
                    baseRequestUrl.toString(),
                    this.helpers.analyzeResponse(baseResponse).getStatusCode() + "",
                    "fastJson scan unknown error",
                    baseRequestResponse
            );
        } finally {
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