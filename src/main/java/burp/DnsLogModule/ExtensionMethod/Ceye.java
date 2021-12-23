package burp.DnsLogModule.ExtensionMethod;

import burp.Bootstrap.CustomHelpers;
import burp.Bootstrap.YamlReader;
import burp.DnsLogModule.ExtensionInterface.DnsLogAbstract;
import burp.IBurpExtenderCallbacks;
import com.github.kevinsawicki.http.HttpRequest;

import java.io.PrintWriter;

public class Ceye extends DnsLogAbstract {
    private IBurpExtenderCallbacks callbacks;

    private String dnslogDomainName;

    private YamlReader yamlReader;

    private String key;
    private String token;
    private String Identifier;

    public Ceye(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        this.dnslogDomainName = "http://api.ceye.io";

        this.setExtensionName("Ceye");

        this.yamlReader = YamlReader.getInstance(callbacks);
        String other = this.yamlReader.getString("dnsLogModule.other");

        this.key = CustomHelpers.randomStr(8);
        this.token = CustomHelpers.getParam(other, "token").trim();
        this.Identifier = CustomHelpers.getParam(other, "Identifier").trim();

        this.init();
    }

    private void init() {
        if (this.token == null || this.token.length() <= 0) {
            throw new RuntimeException(String.format("%s 扩展-token参数不能为空", this.getExtensionName()));
        }
        if (this.Identifier == null || this.Identifier.length() <= 0) {
            throw new RuntimeException(String.format("%s 扩展-Identifier参数不能为空", this.getExtensionName()));
        }

        String temporaryDomainName = this.key + "." + this.Identifier;
        this.setTemporaryDomainName(temporaryDomainName);
    }

    @Override
    public String getBodyContent() {
        String url = String.format("%s/v1/records?token=%s&type=dns&filter=%s", this.dnslogDomainName, this.token, this.key + ".");
        String userAgent = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36";
        HttpRequest request = HttpRequest.get(url);
        request.trustAllCerts();
        request.trustAllHosts();
        request.followRedirects(false);
        request.header("User-Agent", userAgent);
        request.header("Accept", "*/*");
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

        if (body.contains("[]")) {
            return null;
        }
        return body;
    }

    @Override
    public String export() {
        String str1 = String.format("<br/>============dnsLogExtensionDetail============<br/>");
        String str2 = String.format("ExtensionMethod: %s <br/>", this.getExtensionName());
        String str3 = String.format("dnsLogDomainName: %s <br/>", this.dnslogDomainName);
        String str4 = String.format("dnsLogRecordsApi: %s/v1/records?token=%s&type=dns&filter=%s <br/>", this.dnslogDomainName, this.token, this.key + ".");
        String str5 = String.format("dnsLogTemporaryDomainName: %s <br/>", this.getTemporaryDomainName());
        String str6 = String.format("=====================================<br/>");

        String detail = str1 + str2 + str3 + str4 + str5 + str6;

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
        stdout.println(String.format("dnsLogRecordsApi: %s/v1/records?token=%s&type=dns&filter=%s", this.dnslogDomainName, this.token, this.key + "."));
        stdout.println(String.format("dnsLog临时域名: %s", this.getTemporaryDomainName()));
        stdout.println("===================================");
        stdout.println("");
    }
}