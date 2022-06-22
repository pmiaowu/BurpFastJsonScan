package burp.Application.CmdEchoExtension.ExtensionMethod;

import java.net.URL;
import java.util.Date;
import java.util.List;
import java.util.ArrayList;
import java.io.PrintWriter;

import burp.*;

import burp.Bootstrap.*;
import burp.Application.ExtensionInterface.AAppExtension;

import burp.CustomErrorException.TaskTimeoutException;

public class CmdEchoScan extends AAppExtension {
    private GlobalVariableReader globalVariableReader;

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private BurpAnalyzedRequest analyzedRequest;

    private YamlReader yamlReader;

    private List<String> payloads;

    private Date startDate;
    private int maxExecutionTime;

    // 命令输入点
    private String commandInputPoint;
    // 命令输出点
    private String commandOutputPoint;

    public CmdEchoScan(GlobalVariableReader globalVariableReader,
                       IBurpExtenderCallbacks callbacks, BurpAnalyzedRequest analyzedRequest,
                       YamlReader yamlReader, List<String> payloads,
                       Date startDate, Integer maxExecutionTime) {
        this.globalVariableReader = globalVariableReader;

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.analyzedRequest = analyzedRequest;

        this.yamlReader = yamlReader;

        this.payloads = payloads;

        this.startDate = startDate;
        this.maxExecutionTime = maxExecutionTime;

        this.setExtensionName("CmdEchoScan");
        this.registerExtension();

        this.runExtension();
    }

    private void runExtension() {
        for (String payload : this.payloads) {
            // 这个参数为true说明插件已经被卸载,退出所有任务,避免继续扫描
            if (this.globalVariableReader.getBooleanData("isExtensionUnload")) {
                return;
            }

            if (this.isIssue()) {
                return;
            }

            // 判断程序是否运行超时
            Integer startTime = CustomHelpers.getSecondTimestamp(this.startDate);
            Integer currentTime = CustomHelpers.getSecondTimestamp(new Date());
            Integer runTime = currentTime - startTime;
            if (runTime >= this.maxExecutionTime) {
                throw new TaskTimeoutException("scan task timed out");
            }

            // 实际业务处理
            this.cmdEchoDetection(payload);
        }
    }

    private void cmdEchoDetection(String payload) {
        String randomStr = CustomHelpers.randomStr(33);
        String commandInputPointField = this.yamlReader.getString("application.cmdEchoExtension.config.commandInputPointField");
        String commandOutputPointField = this.yamlReader.getString("application.cmdEchoExtension.config.commandOutputPointField");

        String commandInputPointValue = commandInputPointField + ": " + "echo " + randomStr;
        String commandOutputPointValue;
        String cmdEchoData;

        // 发送请求
        List<String> headers = new ArrayList<>();
        headers.add(commandInputPointValue);
        IHttpRequestResponse newHttpRequestResponse = analyzedRequest.makeHttpRequest(payload, headers);

        if (commandOutputPointField.equals("BODY")) {
            String responseBody = new CustomBurpHelpers(this.callbacks).getHttpResponseBody(newHttpRequestResponse.getResponse());
            commandOutputPointValue = randomStr;
            cmdEchoData = findCmdEchoData(responseBody, commandOutputPointValue);
        } else {
            List<String> responseHeaders = this.helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getHeaders();
            commandOutputPointValue = commandOutputPointField + ": " + randomStr;
            cmdEchoData = findCmdEchoData(responseHeaders, commandOutputPointValue);
        }

        if (cmdEchoData.length() == 0) {
            return;
        }

        // 设置问题详情
        this.setIssuesDetail(newHttpRequestResponse, commandInputPointValue, commandOutputPointValue);
    }

    private void setCommandInputPoint(String val) {
        this.commandInputPoint = val;
    }

    private String getCommandInputPoint() {
        return this.commandInputPoint;
    }

    private void setCommandOutputPoint(String val) {
        this.commandOutputPoint = val;
    }

    private String getCommandOutputPoint() {
        return this.commandOutputPoint;
    }

    /**
     * 查找命令回显数据
     * 如果找到了就返回该数据,如果没有就返回空字符串
     *
     * @param arr1 规定要搜索的字符串
     * @param val1 规定要查找的字符串
     * @return
     */
    private String findCmdEchoData(List<String> arr1, String val1) {
        for (String s : arr1) {
            if (s.contains(val1)) {
                return s;
            }
        }
        return "";
    }

    /**
     * 查找命令回显数据
     * 如果找到了就返回该数据,如果没有就返回空字符串
     *
     * @param val1 规定要搜索的字符串
     * @param val2 规定要查找的字符串
     * @return
     */
    private String findCmdEchoData(String val1, String val2) {
        if (val1.contains(val2)) {
            return val2;
        }
        return "";
    }

    /**
     * 设置问题详情
     */
    private void setIssuesDetail(IHttpRequestResponse httpRequestResponse, String val1, String val2) {
        this.setIssueState(true);
        this.setHttpRequestResponse(httpRequestResponse);
        this.setCommandInputPoint(val1);
        this.setCommandOutputPoint(val2);
    }

    @Override
    public IScanIssue export() {
        if (!this.isIssue()) {
            return null;
        }

        IHttpRequestResponse newHttpRequestResponse = this.getHttpRequestResponse();
        URL newHttpRequestUrl = this.helpers.analyzeRequest(newHttpRequestResponse).getUrl();

        String str1 = String.format("<br/>=============CmdEchoExtension============<br/>");
        String str2 = String.format("ExtensionMethod: %s <br/>", this.getExtensionName());
        String str3 = String.format("CommandInputPoint: %s <br/>", this.getCommandInputPoint());
        String str4 = String.format("CommandOutputPoint: %s <br/>", this.getCommandOutputPoint());
        String str5 = String.format("=====================================<br/>");

        String detail = str1 + str2 + str3 + str4 + str5;

        String issueName = this.yamlReader.getString("application.cmdEchoExtension.config.issueName");

        return new CustomScanIssue(
                newHttpRequestUrl,
                issueName,
                0,
                "High",
                "Certain",
                null,
                null,
                detail,
                null,
                new IHttpRequestResponse[]{newHttpRequestResponse},
                newHttpRequestResponse.getHttpService()
        );
    }

    @Override
    public void consoleExport() {
        if (!this.isIssue()) {
            return;
        }

        IHttpRequestResponse newHttpRequestResponse = this.getHttpRequestResponse();
        URL newHttpRequestUrl = this.helpers.analyzeRequest(newHttpRequestResponse).getUrl();
        PrintWriter stdout = new PrintWriter(this.callbacks.getStdout(), true);

        stdout.println("");
        stdout.println("===========CmdEchoExtension详情============");
        stdout.println("你好呀~ (≧ω≦*)喵~");
        stdout.println("这边检测到有一个站点有命令执行 喵~");
        stdout.println(String.format("负责检测的插件: %s", this.getExtensionName()));
        stdout.println(String.format("url: %s", newHttpRequestUrl));
        stdout.println(String.format("命令输入点: %s", this.getCommandInputPoint()));
        stdout.println(String.format("命令输出点: %s", this.getCommandOutputPoint()));
        stdout.println("详情请查看-Burp Scanner模块-Issue activity界面");
        stdout.println("===================================");
        stdout.println("");
    }
}
