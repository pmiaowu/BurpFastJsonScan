package burp.DnsLogModule.ExtensionInterface;

import com.github.kevinsawicki.http.HttpRequest;

public abstract class DnsLogAbstract implements DnsLogInterface {
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
     * 获取扩展名称
     *
     * @return String
     */
    @Override
    public String getExtensionName() {
        return this.extensionName;
    }

    /**
     * 设置临时域名
     *
     * @param value
     */
    protected void setTemporaryDomainName(String value) {
        this.temporaryDomainName = value;
    }

    /**
     * 获取临时域名
     *
     * @return String
     */
    @Override
    public String getTemporaryDomainName() {
        return this.temporaryDomainName;
    }

    /**
     * 发送访问日志
     * <p>
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
        if (this.getTemporaryDomainName() == null || this.getTemporaryDomainName().isEmpty()) {
            throw new IllegalArgumentException("临时域名获取失败, 无法发送日志");
        }

        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("sendAccessLog()方法, value参数不能为空");
        }

        String domainName = "http://" + value + "." + this.getTemporaryDomainName();
        String userAgent = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36";

        HttpRequest request = HttpRequest.get(domainName);
        request.trustAllCerts();
        request.trustAllHosts();
        request.followRedirects(false);
        request.header("User-Agent", userAgent);
        request.header("Accept", "*/*");
        request.readTimeout(3 * 1000);
        request.connectTimeout(3 * 1000);

        try {
            request.ok();
        } catch (Exception e) {
            // 这里选择不处理, 因为发送过去的域名肯定是连接不到的
            // 所以必定爆错, 因此直接屏蔽该接口的爆错即可
        }
    }
}
