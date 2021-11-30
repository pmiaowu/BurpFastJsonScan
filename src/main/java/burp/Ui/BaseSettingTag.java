package burp.Ui;


import java.awt.*;
import java.util.List;
import java.util.ArrayList;
import javax.swing.*;

import burp.IBurpExtenderCallbacks;
import burp.Bootstrap.YamlReader;

public class BaseSettingTag {
    private YamlReader yamlReader;

    private JCheckBox isStartBox;

    private JCheckBox isScanGetJsonBox;
    private JCheckBox isScanPostJsonBox;
    private JCheckBox isScanCookieJsonBox;
    private JCheckBox isScanJsonBox;
    private JCheckBox isScanBodyJsonBox;

    private JCheckBox isStartCmdEchoExtensionBox;
    private JCheckBox isStartRemoteCmdExtensionBox;

    public BaseSettingTag(IBurpExtenderCallbacks callbacks, JTabbedPane tabs, YamlReader yamlReader) {
        JPanel baseSetting = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        this.yamlReader = yamlReader;

        this.input1_1(baseSetting, c);
        this.input1_2(baseSetting, c);

        this.input2_1(baseSetting, c);
        this.input2_2(baseSetting, c);
        this.input2_3(baseSetting, c);
        this.input2_4(baseSetting, c);
        this.input2_5(baseSetting, c);
        this.input2_6(baseSetting, c);

        this.input3_1(baseSetting, c);
        this.input3_2(baseSetting, c);
        this.input3_3(baseSetting, c);

        tabs.addTab("基本设置", baseSetting);
    }

    private void input1_1(JPanel baseSetting, GridBagConstraints c) {
        JLabel br_lbl_1_1 = new JLabel("基础设置");
        br_lbl_1_1.setForeground(new Color(255, 89, 18));
        br_lbl_1_1.setFont(new Font("Serif", Font.PLAIN, br_lbl_1_1.getFont().getSize() + 2));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 1;
        baseSetting.add(br_lbl_1_1, c);
    }

    private void input1_2(JPanel baseSetting, GridBagConstraints c) {
        this.isStartBox = new JCheckBox("插件-启动", this.yamlReader.getBoolean("isStart"));
        this.isStartBox.setFont(new Font("Serif", Font.PLAIN, this.isStartBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 2;
        baseSetting.add(this.isStartBox, c);
    }

    private void input2_1(JPanel baseSetting, GridBagConstraints c) {
        JLabel br_lbl_2_1 = new JLabel("扫描类型设置");
        br_lbl_2_1.setForeground(new Color(255, 89, 18));
        br_lbl_2_1.setFont(new Font("Serif", Font.PLAIN, br_lbl_2_1.getFont().getSize() + 2));
        c.insets = new Insets(15, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 3;
        baseSetting.add(br_lbl_2_1, c);
    }

    private void input2_2(JPanel baseSetting, GridBagConstraints c) {
        this.isScanGetJsonBox = new JCheckBox("扫描Get参数的Json", this.yamlReader.getBoolean("scan.type.isScanGetJson"));
        this.isScanGetJsonBox.setFont(new Font("Serif", Font.PLAIN, this.isScanGetJsonBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 4;
        baseSetting.add(this.isScanGetJsonBox, c);
    }

    private void input2_3(JPanel baseSetting, GridBagConstraints c) {
        this.isScanPostJsonBox = new JCheckBox("扫描Post参数的Json", this.yamlReader.getBoolean("scan.type.isScanPostJson"));
        this.isScanPostJsonBox.setFont(new Font("Serif", Font.PLAIN, this.isScanPostJsonBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 5;
        baseSetting.add(this.isScanPostJsonBox, c);
    }

    private void input2_4(JPanel baseSetting, GridBagConstraints c) {
        this.isScanCookieJsonBox = new JCheckBox("扫描Cookie参数的Json", this.yamlReader.getBoolean("scan.type.isScanCookieJson"));
        this.isScanCookieJsonBox.setFont(new Font("Serif", Font.PLAIN, this.isScanCookieJsonBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 6;
        baseSetting.add(this.isScanCookieJsonBox, c);
    }

    private void input2_5(JPanel baseSetting, GridBagConstraints c) {
        this.isScanJsonBox = new JCheckBox("扫描Post请求的Json", this.yamlReader.getBoolean("scan.type.isScanJson"));
        this.isScanJsonBox.setFont(new Font("Serif", Font.PLAIN, this.isScanJsonBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 7;
        baseSetting.add(this.isScanJsonBox, c);
    }

    private void input2_6(JPanel baseSetting, GridBagConstraints c) {
        this.isScanBodyJsonBox = new JCheckBox("扫描HTTP请求正文的Json", this.yamlReader.getBoolean("scan.type.isScanBodyJson"));
        this.isScanBodyJsonBox.setFont(new Font("Serif", Font.PLAIN, this.isScanBodyJsonBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 8;
        baseSetting.add(this.isScanBodyJsonBox, c);
    }

    private void input3_1(JPanel baseSetting, GridBagConstraints c) {
        JLabel br_lbl_3_1 = new JLabel("应用程序配置");
        br_lbl_3_1.setForeground(new Color(255, 89, 18));
        br_lbl_3_1.setFont(new Font("Serif", Font.PLAIN, br_lbl_3_1.getFont().getSize() + 2));
        c.insets = new Insets(15, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 9;
        baseSetting.add(br_lbl_3_1, c);
    }

    private void input3_2(JPanel baseSetting, GridBagConstraints c) {
        this.isStartCmdEchoExtensionBox = new JCheckBox("命令回显扩展-启动", this.yamlReader.getBoolean("application.cmdEchoExtension.config.isStart"));
        this.isStartCmdEchoExtensionBox.setFont(new Font("Serif", Font.PLAIN, this.isStartCmdEchoExtensionBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 10;
        baseSetting.add(this.isStartCmdEchoExtensionBox, c);
    }

    private void input3_3(JPanel baseSetting, GridBagConstraints c) {
        this.isStartRemoteCmdExtensionBox = new JCheckBox("远程命令扩展-启动", this.yamlReader.getBoolean("application.remoteCmdExtension.config.isStart"));
        this.isStartRemoteCmdExtensionBox.setFont(new Font("Serif", Font.PLAIN, this.isStartRemoteCmdExtensionBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 11;
        baseSetting.add(this.isStartRemoteCmdExtensionBox, c);
    }

    public Boolean isStart() {
        return this.isStartBox.isSelected();
    }

    /**
     * 获取允许运行插入点类型列表
     * 0 = GET, 1 = POST, 2 = COOKIE, 6 = JSON, 36 = BODY
     *
     * @return
     */
    public List<Integer> getScanTypeList() {
        List<Integer> typeList = new ArrayList<>();

        if (this.isScanGetJsonBox.isSelected()) {
            typeList.add(0);
        }

        if (this.isScanPostJsonBox.isSelected()) {
            typeList.add(1);
        }

        if (this.isScanCookieJsonBox.isSelected()) {
            typeList.add(2);
        }

        if (this.isScanJsonBox.isSelected()) {
            typeList.add(6);
        }

        if (this.isScanBodyJsonBox.isSelected()) {
            typeList.add(36);
        }

        return typeList;
    }

    public Boolean isScanJson() {
        return this.isScanJsonBox.isSelected();
    }

    public Boolean isStartCmdEchoExtension() {
        return this.isStartCmdEchoExtensionBox.isSelected();
    }

    public Boolean isStartRemoteCmdExtension() {
        return this.isStartRemoteCmdExtensionBox.isSelected();
    }
}