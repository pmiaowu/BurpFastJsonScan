package burp.DnsLogModule.ExtensionMethod;

import java.io.PrintWriter;

import burp.Bootstrap.CustomHelpers;
import com.github.kevinsawicki.http.HttpRequest;

import burp.IBurpExtenderCallbacks;
import burp.DnsLogModule.ExtensionInterface.DnsLogAbstract;

public class DnsLogCn extends DnsLogAbstract {
    private IBurpExtenderCallbacks callbacks;

    private String dnslogDomainName;

    private String dnsLogCookieName;
    private String dnsLogCookieValue;

    public DnsLogCn(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        this.dnslogDomainName = "http://dnslog.cn";

        this.setExtensionName("DnsLogCn");

        this.init();
    }

    private void init() {
        String url = this.dnslogDomainName + "/getdomain.php";
        String userAgent = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36";

        HttpRequest request = HttpRequest.get(url);
        request.trustAllCerts();
        request.trustAllHosts();
        request.followRedirects(false);
        request.header("User-Agent", userAgent);
        request.header("Accept", "*/*");
        request.readTimeout(30 * 1000);
        request.connectTimeout(30 * 1000);

        int statusCode = request.code();
        if (statusCode != 200) {
            throw new RuntimeException(
                    String.format(
                            "%s 扩展-访问url-%s, 请检查本机是否可访问 %s",
                            this.getExtensionName(),
                            statusCode,
                            url));
        }

        // 设置 dnslog 的临时域名
        String temporaryDomainName = request.body();
        if (request.isBodyEmpty()) {
            throw new RuntimeException(
                    String.format(
                            "%s 扩展-获取临时域名失败, 请检查本机是否可访问 %s",
                            this.getExtensionName(),
                            this.dnslogDomainName));
        }
        this.setTemporaryDomainName(temporaryDomainName);

        String cookie = request.header("Set-Cookie");
        String sessidKey = "PHPSESSID";
        String sessidValue = CustomHelpers.getParam(cookie, sessidKey);
        if (sessidValue.length() == 0) {
            throw new IllegalArgumentException(
                    String.format(
                            "%s 扩展-访问站点 %s 时返回Cookie为空, 导致无法正常获取dnsLog数据, 请检查",
                            this.getExtensionName(),
                            this.dnslogDomainName));
        }

        this.dnsLogCookieName = sessidKey;
        this.dnsLogCookieValue = sessidValue;
    }

    @Override
    public String getBodyContent() {
        String url = this.dnslogDomainName + "/getrecords.php";
        String userAgent = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36";

        HttpRequest request = HttpRequest.get(url);
        request.trustAllCerts();
        request.trustAllHosts();
        request.followRedirects(false);
        request.header("User-Agent", userAgent);
        request.header("Accept", "*/*");
        request.header("Cookie", this.dnsLogCookieName + "=" + this.dnsLogCookieValue + ";");
        request.readTimeout(30 * 1000);
        request.connectTimeout(30 * 1000);

        String body = request.body();

        if (!request.ok()) {
            throw new RuntimeException(
                    String.format(
                            "%s 扩展-%s内容有异常,异常内容: %s",
                            this.getExtensionName(),
                            this.dnslogDomainName,
                            body
                    )
            );
        }

        if (body.equals("[]")) {
            return null;
        }
        return body;
    }

    @Override
    public String export() {
        String str1 = String.format("<br/>============dnsLogExtensionDetail============<br/>");
        String str2 = String.format("ExtensionMethod: %s <br/>", this.getExtensionName());
        String str3 = String.format("dnsLogDomainName: %s <br/>", this.dnslogDomainName);
        String str4 = String.format("dnsLogRecordsApi: %s <br/>", this.dnslogDomainName + "/getrecords.php");
        String str5 = String.format("cookie: %s=%s <br/>", this.dnsLogCookieName, this.dnsLogCookieValue);
        String str6 = String.format("dnsLogTemporaryDomainName: %s <br/>", this.getTemporaryDomainName());
        String str7 = String.format("=====================================<br/>");

        String detail = str1 + str2 + str3 + str4 + str5 + str6 + str7;

        return detail;
    }

    @Override
    public void consoleExport() {
        PrintWriter stdout = new PrintWriter(this.callbacks.getStdout(), true);

        stdout.println("");
        stdout.println("===========dnsLog扩展详情===========");
        stdout.println("你好呀~ (≧ω≦*)喵~");
        stdout.println(String.format("被调用的插件: %s", this.getExtensionName()));
        stdout.println(String.format("dnsLog域名: %s", this.dnslogDomainName));
        stdout.println(String.format("dnsLog保存记录的api接口: %s", this.dnslogDomainName + "/getrecords.php"));
        stdout.println(String.format("cookie: %s=%s", this.dnsLogCookieName, this.dnsLogCookieValue));
        stdout.println(String.format("dnsLog临时域名: %s", this.getTemporaryDomainName()));
        stdout.println("===================================");
        stdout.println("");
    }
}
