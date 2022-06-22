package burp.Application.RemoteCmdExtension;

import java.util.Date;
import java.util.List;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import burp.Bootstrap.GlobalVariableReader;
import burp.IBurpExtenderCallbacks;

import burp.DnsLogModule.DnsLog;
import burp.Bootstrap.YamlReader;
import burp.Bootstrap.BurpAnalyzedRequest;
import burp.Application.ExtensionInterface.IAppExtension;

public class RemoteCmd {
    private GlobalVariableReader globalVariableReader;

    private IBurpExtenderCallbacks callbacks;

    private BurpAnalyzedRequest analyzedRequest;

    private DnsLog dnsLog;

    private YamlReader yamlReader;

    private IAppExtension remoteCmd;

    // 该模块启动日期
    private Date startDate = new Date();

    public RemoteCmd(
            GlobalVariableReader globalVariableReader,
            IBurpExtenderCallbacks callbacks,
            BurpAnalyzedRequest analyzedRequest,
            DnsLog dnsLog,
            YamlReader yamlReader,
            String callClassName) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
        this.globalVariableReader = globalVariableReader;

        this.callbacks = callbacks;
        this.analyzedRequest = analyzedRequest;

        this.dnsLog = dnsLog;

        this.yamlReader = yamlReader;
        this.init(callClassName);
    }

    private void init(String callClassName) throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        if (callClassName == null || callClassName.length() <= 0) {
            throw new IllegalArgumentException("Application.RemoteCmdExtension-请输入要调用的插件名称");
        }

        List<String> payloads = this.yamlReader.getStringList("application.remoteCmdExtension.config.payloads");
        if (payloads.size() == 0) {
            throw new IllegalArgumentException("Application.RemoteCmdExtension-获取的payloads为空,无法正常运行");
        }

        Class c = Class.forName("burp.Application.RemoteCmdExtension.ExtensionMethod." + callClassName);
        Constructor cConstructor = c.getConstructor(
                GlobalVariableReader.class,
                IBurpExtenderCallbacks.class,
                BurpAnalyzedRequest.class,
                DnsLog.class,
                YamlReader.class,
                List.class,
                Date.class,
                Integer.class);
        this.remoteCmd = (IAppExtension) cConstructor.newInstance(
                this.globalVariableReader,
                this.callbacks,
                this.analyzedRequest,
                this.dnsLog,
                this.yamlReader,
                payloads,
                this.startDate,
                this.getMaxExecutionTime());

        if (!this.remoteCmd.isRegister()) {
            throw new IllegalArgumentException("该应用模块未注册,无法使用");
        }

        if (this.remoteCmd.getExtensionName().isEmpty()) {
            throw new IllegalArgumentException("请为该该应用模块-设置扩展名称");
        }
    }

    public IAppExtension run() {
        return this.remoteCmd;
    }

    /**
     * 程序最大执行时间,单位为秒
     * 会根据payload的添加而添加
     *
     * @return
     */
    private Integer getMaxExecutionTime() {
        Integer maxExecutionTime = this.yamlReader.getInteger("application.remoteCmdExtension.config.maxExecutionTime");
        Integer keySize = this.yamlReader.getStringList("application.remoteCmdExtension.config.payloads").size();
        maxExecutionTime += keySize * 6;
        return maxExecutionTime;
    }
}
