package burp.Application.CmdEchoExtension;

import java.util.Date;
import java.util.List;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import burp.Bootstrap.GlobalVariableReader;
import burp.IBurpExtenderCallbacks;

import burp.Bootstrap.YamlReader;
import burp.Bootstrap.BurpAnalyzedRequest;
import burp.Application.ExtensionInterface.IAppExtension;

public class CmdEcho {
    private GlobalVariableReader globalVariableReader;

    private IBurpExtenderCallbacks callbacks;

    private BurpAnalyzedRequest analyzedRequest;

    private YamlReader yamlReader;

    private IAppExtension cmdEcho;

    // 该模块启动日期
    private Date startDate = new Date();

    public CmdEcho(
            GlobalVariableReader globalVariableReader,
            IBurpExtenderCallbacks callbacks,
            BurpAnalyzedRequest analyzedRequest,
            YamlReader yamlReader,
            String callClassName) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
        this.globalVariableReader = globalVariableReader;

        this.callbacks = callbacks;
        this.analyzedRequest = analyzedRequest;

        this.yamlReader = yamlReader;
        this.init(callClassName);
    }

    private void init(String callClassName) throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        if (callClassName == null || callClassName.length() <= 0) {
            throw new IllegalArgumentException("Application.CmdEchoExtension-请输入要调用的插件名称");
        }

        List<String> payloads = this.yamlReader.getStringList("application.cmdEchoExtension.config.payloads");
        if (payloads.size() == 0) {
            throw new IllegalArgumentException("Application.CmdEchoExtension-获取的payloads为空,无法正常运行");
        }

        Class c = Class.forName("burp.Application.CmdEchoExtension.ExtensionMethod." + callClassName);
        Constructor cConstructor = c.getConstructor(
                GlobalVariableReader.class,
                IBurpExtenderCallbacks.class,
                BurpAnalyzedRequest.class,
                YamlReader.class,
                List.class,
                Date.class,
                Integer.class);
        this.cmdEcho = (IAppExtension) cConstructor.newInstance(
                this.globalVariableReader,
                this.callbacks,
                this.analyzedRequest,
                this.yamlReader,
                payloads,
                this.startDate,
                this.getMaxExecutionTime());

        if (!this.cmdEcho.isRegister()) {
            throw new IllegalArgumentException("该应用模块未注册,无法使用");
        }

        if (this.cmdEcho.getExtensionName().isEmpty()) {
            throw new IllegalArgumentException("请为该该应用模块-设置扩展名称");
        }
    }

    public IAppExtension run() {
        return this.cmdEcho;
    }

    /**
     * 程序最大执行时间,单位为秒
     * 会根据payload的添加而添加
     *
     * @return
     */
    private Integer getMaxExecutionTime() {
        Integer maxExecutionTime = this.yamlReader.getInteger("application.cmdEchoExtension.config.maxExecutionTime");
        Integer keySize = this.yamlReader.getStringList("application.cmdEchoExtension.config.payloads").size();
        maxExecutionTime += keySize * 6;
        return maxExecutionTime;
    }
}
