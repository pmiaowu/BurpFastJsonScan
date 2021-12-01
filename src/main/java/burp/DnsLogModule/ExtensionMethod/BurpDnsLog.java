package burp.DnsLogModule.ExtensionMethod;

import java.util.Map;
import java.util.List;
import java.util.Arrays;
import java.util.Iterator;
import java.io.PrintWriter;

import burp.IExtensionHelpers;
import burp.IBurpExtenderCallbacks;
import burp.IBurpCollaboratorInteraction;
import burp.IBurpCollaboratorClientContext;
import burp.DnsLogModule.ExtensionInterface.DnsLogAbstract;

public class BurpDnsLog extends DnsLogAbstract {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private IBurpCollaboratorClientContext burpCollaboratorClientContext;

    private String dnslogContent = null;

    public BurpDnsLog(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.burpCollaboratorClientContext = callbacks.createBurpCollaboratorClientContext();

        setExtensionName("BurpDnsLog");

        this.init();
    }

    private void init() {
        // 通过burp组建获取临时dnslog域名
        String temporaryDomainName = this.burpCollaboratorClientContext.generatePayload(true);
        if (temporaryDomainName == null || temporaryDomainName.length() <= 0) {
            throw new RuntimeException(
                    String.format(
                            "%s 扩展-获取临时域名失败, 请检查本机是否可使用burp自带的dnslog客户端",
                            this.getExtensionName()));
        }
        this.setTemporaryDomainName(temporaryDomainName);
    }

    @Override
    public String getBodyContent() {
        List<IBurpCollaboratorInteraction> collaboratorInteractions =
                this.burpCollaboratorClientContext.fetchCollaboratorInteractionsFor(this.getTemporaryDomainName());
        if (collaboratorInteractions != null && !collaboratorInteractions.isEmpty()) {
            Iterator<IBurpCollaboratorInteraction> iterator = collaboratorInteractions.iterator();

            Map<String, String> properties = iterator.next().getProperties();
            if (properties.size() == 0) {
                return this.dnslogContent;
            }

            String content = null;
            for (String property : properties.keySet()) {
                String text = properties.get(property);
                if (property.equals("raw_query")) {
                    text = new String(this.helpers.base64Decode(text));
                }
                content += text + " ";
            }
            this.dnslogContent += content;
            return this.dnslogContent;
        }
        return this.dnslogContent;
    }

    @Override
    public String export() {
        String str1 = String.format("<br/>============dnsLogExtensionDetail============<br/>");
        String str2 = String.format("ExtensionMethod: %s <br/>", this.getExtensionName());
        String str3 = String.format("dnsLogTemporaryDomainName: %s <br/>", this.getTemporaryDomainName());
        String str4 = String.format("=====================================<br/>");

        String detail = str1 + str2 + str3 + str4;

        return detail;
    }

    @Override
    public void consoleExport() {
        PrintWriter stdout = new PrintWriter(this.callbacks.getStdout(), true);

        stdout.println("");
        stdout.println("===========dnsLog扩展详情===========");
        stdout.println("你好呀~ (≧ω≦*)喵~");
        stdout.println(String.format("被调用的插件: %s", this.getExtensionName()));
        stdout.println(String.format("dnsLog临时域名: %s", this.getTemporaryDomainName()));
        stdout.println("===================================");
        stdout.println("");
    }
}
