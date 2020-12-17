package burp.DnsLogModule.ExtensionMethod;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import java.io.IOException;

/**
 * DnsLog扩展的抽象类
 * 所有的DnsLog检测的方法都要继承它并实现所有的接口
 */
abstract class DnsLogAbstract implements DnsLogInterface {
    private String extensionName = "";

    private String temporaryDomainName;

    /**
     * 设置扩展名称 (必须的)
     *
     * @param value
     */
    protected void setExtensionName(String value) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("DnsLog扩展-扩展名称不能为空");
        }
        this.extensionName = value;
    }

    /**
     * 扩展名称检查
     * 作用: 让所有不设置扩展名称的扩展无法正常使用, 防止直接调用本类的其他方法, 保证扩展的正常
     */
    private void extensionNameCheck() {
        if (this.extensionName == null || this.extensionName.isEmpty()) {
            throw new IllegalArgumentException("请为该DnsLog扩展-设置扩展名称");
        }
    }

    /**
     * 获取扩展名称
     *
     * @return String
     */
    @Override
    public String getExtensionName() {
        this.extensionNameCheck();
        return this.extensionName;
    }

    /**
     * 设置临时域名
     *
     * @param value
     */
    protected void setTemporaryDomainName(String value) {
        this.extensionNameCheck();
        this.temporaryDomainName = value;
    }

    /**
     * 获取临时域名
     *
     * @return String
     */
    @Override
    public String getTemporaryDomainName() {
        this.extensionNameCheck();
        return this.temporaryDomainName;
    }

    /**
     * 发送访问日志
     * 
     * 根据传进来的 value 进行域名拼接, 接着以http get请求进行访问
     * 例如:
     * 临时域名: fs.dnslog.cn
     * value: testlog
     * 拼接：http://testlog.fs.dnslog.cn 然后以http get请求进行访问,结束
     *
     * @param value
     */
    @Override
    public void sendAccessLog(String value) {
        this.extensionNameCheck();

        if (this.getTemporaryDomainName() == null || this.getTemporaryDomainName().isEmpty()) {
            throw new IllegalArgumentException("临时域名获取失败, 无法发送日志");
        }

        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("sendAccessLog()方法, value参数不能为空");
        }

        String domainName = "http://" + value + "." + this.getTemporaryDomainName();

        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpClientContext context = HttpClientContext.create();
        HttpGet httpGet = new HttpGet(domainName);

        CloseableHttpResponse response = null;
        try {
            response = httpClient.execute(httpGet, context);
        } catch (Exception e) {
            // 这里选择不处理, 因为发送过去的域名肯定是连接不到的
            // 所以必定爆错, 因此直接屏蔽该接口的爆错即可
        } finally {
            try {
                if (response != null) {
                    response.close();
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
