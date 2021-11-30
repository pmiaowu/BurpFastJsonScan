package burp.DnsLogModule;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import burp.IBurpExtenderCallbacks;
import burp.DnsLogModule.ExtensionInterface.DnsLogInterface;

public class DnsLog {
    private DnsLogInterface dnsLog;

    public DnsLog(IBurpExtenderCallbacks callbacks, String callClassName) throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        if (callClassName == null || callClassName.length() <= 0) {
            throw new IllegalArgumentException("DnsLog模块-请输入要调用的dnsLog插件");
        }

        Class c = Class.forName("burp.DnsLogModule.ExtensionMethod." + callClassName);
        Constructor cConstructor = c.getConstructor(IBurpExtenderCallbacks.class);
        this.dnsLog = (DnsLogInterface) cConstructor.newInstance(callbacks);

        if (this.dnsLog.getExtensionName().isEmpty()) {
            throw new IllegalArgumentException("请为该DnsLog扩展-设置扩展名称");
        }
    }

    public DnsLogInterface run() {
        return this.dnsLog;
    }
}