package burp.DnsLogModule.ExtensionInterface;

/**
 * DnsLog扩展的公共接口
 * 所有的抽象类都要继承它并实现所有的接口
 */
public interface DnsLogInterface {
    String getExtensionName();

    String getTemporaryDomainName();

    String getBodyContent();

    void sendAccessLog(String value);

    String export();

    void consoleExport();
}