package burp;

import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;

import burp.Application.CmdEchoExtension.CmdEcho;
import burp.Ui.Tags;
import burp.DnsLogModule.DnsLog;
import burp.Bootstrap.YamlReader;
import burp.Bootstrap.CustomBurpUrl;
import burp.Bootstrap.BurpAnalyzedRequest;
import burp.Bootstrap.GlobalVariableReader;
import burp.CustomErrorException.TaskTimeoutException;
import burp.Application.RemoteCmdExtension.RemoteCmd;

public class BurpExtender implements IBurpExtender, IScannerCheck, IExtensionStateListener {
    public static String NAME = "FastJsonScan";
    public static String VERSION = "2.2.2";

    private GlobalVariableReader globalVariableReader;

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private PrintWriter stdout;
    private PrintWriter stderr;

    private Tags tags;

    private YamlReader yamlReader;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        // 全局变量的数据保存地址
        // 用于在程序执行的过程中能够实时的修改变量数据使用
        this.globalVariableReader = new GlobalVariableReader();

        // 是否卸载扩展
        // 用于卸载插件以后,把程序快速退出去,避免卡顿
        // true = 已被卸载, false = 未卸载
        this.globalVariableReader.putBooleanData("isExtensionUnload", false);

        // 标签界面
        this.tags = new Tags(callbacks, NAME);

        // 配置文件
        this.yamlReader = YamlReader.getInstance(callbacks);

        callbacks.setExtensionName(NAME);
        callbacks.registerScannerCheck(this);
        callbacks.registerExtensionStateListener(this);

        // 基本信息输出
        // 作者拿来臭美用的 ╰(*°▽°*)╯
        this.stdout.println(basicInformationOutput());
    }

    /**
     * 基本信息输出
     */
    private static String basicInformationOutput() {
        String str1 = "===================================\n";
        String str2 = String.format("%s 加载成功\n", NAME);
        String str3 = String.format("版本: %s\n", VERSION);
        String str4 = "作者: P喵呜-PHPoop\n";
        String str5 = "QQ: 3303003493\n";
        String str6 = "微信: a3303003493\n";
        String str7 = "GitHub: https://github.com/pmiaowu\n";
        String str8 = "Blog: https://www.yuque.com/pmiaowu\n";
        String str9 = String.format("下载地址: %s\n", "https://github.com/pmiaowu/BurpFastJsonScan");
        String str10 = "===================================\n";
        String detail = str1 + str2 + str3 + str4 + str5 + str6 + str7 + str8 + str9 + str10;
        return detail;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        List<String> domainNameBlacklist = this.yamlReader.getStringList("scan.domainName.blacklist");
        List<String> domainNameWhitelist = this.yamlReader.getStringList("scan.domainName.whitelist");

        // 基础url解析
        CustomBurpUrl baseBurpUrl = new CustomBurpUrl(this.callbacks, baseRequestResponse);

        // 基础请求分析
        BurpAnalyzedRequest baseAnalyzedRequest = new BurpAnalyzedRequest(this.callbacks, this.tags, baseRequestResponse);

        // 消息等级-用于插件扫描队列界面的显示
        String messageLevel = this.yamlReader.getString("messageLevel");

        // 判断是否开启插件
        if (!this.tags.getBaseSettingTagClass().isStart()) {
            return null;
        }

        // 判断域名黑名单
        if (domainNameBlacklist != null && domainNameBlacklist.size() >= 1) {
            if (isMatchDomainName(baseBurpUrl.getRequestHost(), domainNameBlacklist)) {
                return null;
            }
        }

        // 判断域名白名单
        if (domainNameWhitelist != null && domainNameWhitelist.size() >= 1) {
            if (!isMatchDomainName(baseBurpUrl.getRequestHost(), domainNameWhitelist)) {
                return null;
            }
        }

        // 判断当前请求后缀,是否为url黑名单后缀
        if (this.isUrlBlackListSuffix(baseBurpUrl)) {
            return null;
        }

        // 判断是否有允许扫描的JSON类型
        if (this.tags.getBaseSettingTagClass().getScanTypeList().size() == 0) {
            return null;
        }

        // 判断当前请求是否有json
        if (!baseAnalyzedRequest.isRequestParameterContentJson()) {
            if (messageLevel.equals("ALL")) {
                this.tags.getScanQueueTagClass().add(
                        "",
                        this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                        baseBurpUrl.getHttpRequestUrl().toString(),
                        this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() + "",
                        "request no json",
                        baseRequestResponse
                );
            }
            return null;
        }

        // 判断当前请求是否有符合条件的json
        if (!baseAnalyzedRequest.isSiteEligibleJson()) {
            if (messageLevel.equals("ALL")) {
                this.tags.getScanQueueTagClass().add(
                        "",
                        this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                        baseBurpUrl.getHttpRequestUrl().toString(),
                        this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() + "",
                        "request json no eligible",
                        baseRequestResponse
                );
            }
            return null;
        }

        // 判断当前站点问题数量是否超出了
        Integer issueNumber = this.yamlReader.getInteger("scan.issueNumber");
        if (issueNumber != 0) {
            Integer siteIssueNumber = this.getSiteIssueNumber(baseBurpUrl.getRequestDomainName());
            if (siteIssueNumber >= issueNumber) {
                if (messageLevel.equals("ALL") || messageLevel.equals("INFO")) {
                    this.tags.getScanQueueTagClass().add(
                            "",
                            this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                            baseBurpUrl.getHttpRequestUrl().toString(),
                            this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() + "",
                            "the number of website problems has exceeded",
                            baseRequestResponse
                    );
                }
                return null;
            }
        }

        // 判断当前站点是否超出扫描数量了
        Integer siteScanNumber = this.yamlReader.getInteger("scan.siteScanNumber");
        if (siteScanNumber != 0) {
            Integer siteJsonNumber = this.getSiteJsonNumber(baseBurpUrl.getRequestDomainName());
            if (siteJsonNumber >= siteScanNumber) {
                if (messageLevel.equals("ALL") || messageLevel.equals("INFO")) {
                    this.tags.getScanQueueTagClass().add(
                            "",
                            this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                            baseBurpUrl.getHttpRequestUrl().toString(),
                            this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() + "",
                            "the number of website scans exceeded",
                            baseRequestResponse
                    );
                }
                return null;
            }
        }

        // 添加任务到面板中等待检测
        int tagId = this.tags.getScanQueueTagClass().add(
                "",
                this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                baseBurpUrl.getHttpRequestUrl().toString(),
                this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() + "",
                "waiting for test results",
                baseRequestResponse
        );

        try {
            // cmd回显扩展
            IScanIssue cmdEchoIssuesDetail = this.cmdEchoExtension(tagId, baseAnalyzedRequest);
            if (cmdEchoIssuesDetail != null) {
                issues.add(cmdEchoIssuesDetail);
                return issues;
            }

            // 远程cmd扩展
            IScanIssue remoteCmdIssuesDetail = this.remoteCmdExtension(tagId, baseAnalyzedRequest);
            if (remoteCmdIssuesDetail != null) {
                issues.add(remoteCmdIssuesDetail);
                return issues;
            }

            // 未检测出来问题, 更新任务状态至任务栏面板
            this.tags.getScanQueueTagClass().save(
                    tagId,
                    "ALL",
                    this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                    baseBurpUrl.getHttpRequestUrl().toString(),
                    this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() + "",
                    "[-] not found fastJson command execution",
                    baseRequestResponse
            );
        } catch (TaskTimeoutException e) {
            this.stdout.println("========插件错误-超时错误============");
            this.stdout.println(String.format("url: %s", baseBurpUrl.getHttpRequestUrl().toString()));
            this.stdout.println("请使用该url重新访问,若是还多次出现此错误,则很有可能waf拦截");
            this.stdout.println("错误详情请查看Extender里面对应插件的Errors标签页");
            this.stdout.println("========================================");
            this.stdout.println(" ");

            this.tags.getScanQueueTagClass().save(
                    tagId,
                    "",
                    this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                    baseBurpUrl.getHttpRequestUrl().toString(),
                    this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() + "",
                    "[x] scan task timed out",
                    baseRequestResponse
            );

            e.printStackTrace(this.stderr);
        } catch (Exception e) {
            this.stdout.println("========插件错误-未知错误============");
            this.stdout.println(String.format("url: %s", baseBurpUrl.getHttpRequestUrl().toString()));
            this.stdout.println("请使用该url重新访问,若是还多次出现此错误,则很有可能waf拦截");
            this.stdout.println("错误详情请查看Extender里面对应插件的Errors标签页");
            this.stdout.println("========================================");
            this.stdout.println(" ");

            this.tags.getScanQueueTagClass().save(
                    tagId,
                    "",
                    this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                    baseBurpUrl.getHttpRequestUrl().toString(),
                    this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() + "",
                    "[x] unknown error",
                    baseRequestResponse
            );

            e.printStackTrace(this.stderr);
        } finally {
            this.stdout.println("================扫描完毕================");
            this.stdout.println(String.format("url: %s", baseBurpUrl.getHttpRequestUrl().toString()));
            this.stdout.println("========================================");
            this.stdout.println(" ");

            return issues;
        }
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    /**
     * 命令回显扩展
     *
     * @param tagId
     * @param analyzedRequest
     * @return IScanIssue issues
     * @throws ClassNotFoundException
     * @throws NoSuchMethodException
     * @throws InvocationTargetException
     * @throws InstantiationException
     * @throws IllegalAccessException
     */
    private IScanIssue cmdEchoExtension(int tagId, BurpAnalyzedRequest analyzedRequest) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
        String provider = this.yamlReader.getString("application.cmdEchoExtension.config.provider");

        if (!this.tags.getBaseSettingTagClass().isStartCmdEchoExtension()) {
            return null;
        }

        CmdEcho cmdEcho = new CmdEcho(this.globalVariableReader, this.callbacks, analyzedRequest, this.yamlReader, provider);
        if (!cmdEcho.run().isIssue()) {
            return null;
        }

        IHttpRequestResponse httpRequestResponse = cmdEcho.run().getHttpRequestResponse();

        this.tags.getScanQueueTagClass().save(
                tagId,
                cmdEcho.run().getExtensionName(),
                this.helpers.analyzeRequest(httpRequestResponse).getMethod(),
                new CustomBurpUrl(this.callbacks, httpRequestResponse).getHttpRequestUrl().toString(),
                this.helpers.analyzeResponse(httpRequestResponse.getResponse()).getStatusCode() + "",
                "[+] found fastJson command execution",
                cmdEcho.run().getHttpRequestResponse()
        );

        cmdEcho.run().consoleExport();
        return cmdEcho.run().export();
    }

    /**
     * 远程cmd扩展
     *
     * @param tagId
     * @param analyzedRequest
     * @return IScanIssue issues
     * @throws ClassNotFoundException
     * @throws NoSuchMethodException
     * @throws InvocationTargetException
     * @throws InstantiationException
     * @throws IllegalAccessException
     */
    private IScanIssue remoteCmdExtension(int tagId, BurpAnalyzedRequest analyzedRequest) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
        String provider = this.yamlReader.getString("application.remoteCmdExtension.config.provider");

        if (!this.tags.getBaseSettingTagClass().isStartRemoteCmdExtension()) {
            return null;
        }

        DnsLog dnsLog = new DnsLog(this.callbacks, this.yamlReader.getString("dnsLogModule.provider"));
        RemoteCmd remoteCmd = new RemoteCmd(this.globalVariableReader, this.callbacks, analyzedRequest, dnsLog, this.yamlReader, provider);
        if (!remoteCmd.run().isIssue()) {
            return null;
        }

        IHttpRequestResponse httpRequestResponse = remoteCmd.run().getHttpRequestResponse();

        this.tags.getScanQueueTagClass().save(
                tagId,
                remoteCmd.run().getExtensionName(),
                this.helpers.analyzeRequest(httpRequestResponse).getMethod(),
                new CustomBurpUrl(this.callbacks, httpRequestResponse).getHttpRequestUrl().toString(),
                this.helpers.analyzeResponse(httpRequestResponse.getResponse()).getStatusCode() + "",
                "[+] found fastJson command execution",
                remoteCmd.run().getHttpRequestResponse()
        );

        remoteCmd.run().consoleExport();
        return remoteCmd.run().export();
    }

    /**
     * 网站问题数量
     *
     * @param domainName
     * @return
     */
    private Integer getSiteIssueNumber(String domainName) {
        Integer number = 0;

        String issueName = this.yamlReader.getString("application.cmdEchoExtension.config.issueName");
        String issueName2 = this.yamlReader.getString("application.remoteCmdExtension.config.issueName");

        for (IScanIssue Issue : this.callbacks.getScanIssues(domainName)) {
            if (Issue.getIssueName().equals(issueName) || Issue.getIssueName().equals(issueName2)) {
                number++;
            }
        }

        return number;
    }

    /**
     * 站点JSON出现数量
     *
     * @param domainName
     * @return
     */
    private Integer getSiteJsonNumber(String domainName) {
        Integer number = 0;
        for (IHttpRequestResponse requestResponse : this.callbacks.getSiteMap(domainName)) {
            BurpAnalyzedRequest analyzedRequest = new BurpAnalyzedRequest(this.callbacks, this.tags, requestResponse);
            if (analyzedRequest.isRequestParameterContentJson()) {
                number++;
            }
        }
        return number;
    }

    /**
     * 判断是否查找的到指定的域名
     *
     * @param domainName     需匹配的域名
     * @param domainNameList 待匹配的域名列表
     * @return
     */
    private static Boolean isMatchDomainName(String domainName, List<String> domainNameList) {
        domainName = domainName.trim();

        if (domainName.length() <= 0) {
            return false;
        }

        if (domainNameList == null || domainNameList.size() <= 0) {
            return false;
        }

        if (domainName.contains(":")) {
            domainName = domainName.substring(0, domainName.indexOf(":"));
        }

        String reverseDomainName = new StringBuffer(domainName).reverse().toString();

        for (String domainName2 : domainNameList) {
            domainName2 = domainName2.trim();

            if (domainName2.length() <= 0) {
                continue;
            }

            if (domainName2.contains(":")) {
                domainName2 = domainName2.substring(0, domainName2.indexOf(":"));
            }

            String reverseDomainName2 = new StringBuffer(domainName2).reverse().toString();

            if (domainName.equals(domainName2)) {
                return true;
            }

            if (reverseDomainName.contains(".") && reverseDomainName2.contains(".")) {
                List<String> splitDomainName = new ArrayList<String>(Arrays.asList(reverseDomainName.split("[.]")));

                List<String> splitDomainName2 = new ArrayList<String>(Arrays.asList(reverseDomainName2.split("[.]")));

                if (splitDomainName.size() <= 0 || splitDomainName2.size() <= 0) {
                    continue;
                }

                if (splitDomainName.size() < splitDomainName2.size()) {
                    for (int i = splitDomainName.size(); i < splitDomainName2.size(); i++) {
                        splitDomainName.add("*");
                    }
                }

                if (splitDomainName.size() > splitDomainName2.size()) {
                    for (int i = splitDomainName2.size(); i < splitDomainName.size(); i++) {
                        splitDomainName2.add("*");
                    }
                }

                int ii = 0;
                for (int i = 0; i < splitDomainName.size(); i++) {
                    if (splitDomainName2.get(i).equals("*")) {
                        ii = ii + 1;
                    } else if (splitDomainName.get(i).equals(splitDomainName2.get(i))) {
                        ii = ii + 1;
                    }
                }

                if (ii == splitDomainName.size()) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 判断是否url黑名单后缀
     * 大小写不区分
     * 是 = true, 否 = false
     *
     * @param burpUrl
     * @return
     */
    private boolean isUrlBlackListSuffix(CustomBurpUrl burpUrl) {
        if (!this.yamlReader.getBoolean("urlBlackListSuffix.config.isStart")) {
            return false;
        }

        String noParameterUrl = burpUrl.getHttpRequestUrl().toString().split("\\?")[0];
        String urlSuffix = noParameterUrl.substring(noParameterUrl.lastIndexOf(".") + 1);

        List<String> suffixList = this.yamlReader.getStringList("urlBlackListSuffix.suffixList");
        if (suffixList == null || suffixList.size() == 0) {
            return false;
        }

        for (String s : suffixList) {
            if (s.toLowerCase().equals(urlSuffix.toLowerCase())) {
                return true;
            }
        }

        return false;
    }

    @Override
    public void extensionUnloaded() {
        this.globalVariableReader.putBooleanData("isExtensionUnload", true);
    }
}
