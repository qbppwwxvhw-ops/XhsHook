package com.example.xhshook;

import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.os.Build;

import java.io.File;
import java.lang.reflect.Field;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class XhsAntiDetectHook implements IXposedHookLoadPackage {

    private static final String TAG = "XhsHook";
    private static final String TARGET_PKG = "com.xingin.xhs";

    /** 每条日志只打印一次，避免刷屏 */
    private final Set<String> loggedOnce = new HashSet<>();

    private void logOnce(String msg) {
        if (loggedOnce.add(msg)) {
            XposedBridge.log(msg);
        }
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!TARGET_PKG.equals(lpparam.packageName)) return;
        XposedBridge.log(TAG + ": XHS已加载，开始注入Hook");

        hookCallJavaJniTest(lpparam.classLoader);
        hookNativeGatherTest(lpparam.classLoader);
        hookBasicJniTest(lpparam.classLoader);
        hookVpnDetection(lpparam.classLoader);
        hookDebugDetection();
        hookRootExecDetection();
        hookSystemProperties();
        hookPackageManager();
        hookFileExists();
        hookBuildFields();
    }

    // ================================================================
    // CallJavaJniTest
    // ================================================================
    private void hookCallJavaJniTest(ClassLoader cl) {
        final String CLASS = "com.xingin.a.a.f.jni.CallJavaJniTest";

        // Xposed 检测
        hookReturn(cl, CLASS, "existXposed", false);
        hookReturn(cl, CLASS, "getCheckingXposedResult", 0);
        hookReturn(cl, CLASS, "getCheckingVirtualAppResult", 0);

        // 无障碍检测
        hookReturn(cl, CLASS, "getAccessibilityStatus", 0);
        hookReturn(cl, CLASS, "getEnabledAccessibilityServices", "");

        // 进程枚举
        hookReturn(cl, CLASS, "getRunningProcessListByCommand", new ArrayList<String>());
        hookReturn(cl, CLASS, "getRunningProcessListBySdkApi", new ArrayList<String>());

        // 隐藏应用列表
        hookReturn(cl, CLASS, "getSecretAppList", new ArrayList<String>());

        // 开发者选项
        hookReturn(cl, CLASS, "devOpenedCount", 0);

        // 安装列表过滤
        hookMethod(cl, CLASS, "getInstallApps", new XC_MethodHook() {
            @Override
            @SuppressWarnings("unchecked")
            protected void afterHookedMethod(MethodHookParam param) {
                Object result = param.getResult();
                if (result instanceof List) {
                    List<String> list = new ArrayList<>((List<String>) result);
                    list.removeIf(pkg -> pkg != null && isSensitivePkg(pkg));
                    param.setResult(list);
                }
            }
        });
    }

    // ================================================================
    // NativeGatherTest
    // ================================================================
    private void hookNativeGatherTest(ClassLoader cl) {
        final String CLASS = "com.xingin.a.a.f.jni.NativeGatherTest";

        hookReturn(cl, CLASS, "isRoot", false);
        hookReturn(cl, CLASS, "isPtrace", false);

        hookMethod(cl, CLASS, "mapsInfo", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                Object result = param.getResult();
                if (result instanceof String) {
                    param.setResult(filterMapsInfo((String) result));
                }
            }
        });

        hookMethod(cl, CLASS, "getProcessName", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                Object result = param.getResult();
                if (result instanceof String && isSensitivePkg((String) result)) {
                    param.setResult("com.xingin.xhs");
                }
            }
        });
    }

    // ================================================================
    // BasicJniTest
    // ================================================================
    private void hookBasicJniTest(ClassLoader cl) {
        final String CLASS = "com.xingin.a.a.f.jni.BasicJniTest";
        hookReturn(cl, CLASS, "isDebugAble", false);
        hookReturn(cl, CLASS, "getBuildIsEmulator", false);
    }

    // ================================================================
    // VPN 检测 - Hook 系统层
    // ================================================================
    private void hookVpnDetection(ClassLoader cl) {
        // TRANSPORT_VPN = 4
        try {
            XposedHelpers.findAndHookMethod(
                NetworkCapabilities.class,
                "hasTransport",
                int.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        int transport = (int) param.args[0];
                        if (transport == 4) {
                            XposedBridge.log(TAG + ": hasTransport(VPN) 拦截 → false");
                            param.setResult(false);
                        }
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": hasTransport hook失败 → " + e.getMessage());
        }

        // NET_CAPABILITY_NOT_VPN = 15
        try {
            XposedHelpers.findAndHookMethod(
                NetworkCapabilities.class,
                "hasCapability",
                int.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        int cap = (int) param.args[0];
                        if (cap == 15) {
                            XposedBridge.log(TAG + ": hasCapability(NOT_VPN) 拦截 → true");
                            param.setResult(true);
                        }
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": hasCapability hook失败 → " + e.getMessage());
        }

        // 过滤 tun0/ppp0 等 VPN 网卡
        try {
            XposedHelpers.findAndHookMethod(
                NetworkInterface.class,
                "getNetworkInterfaces",
                new XC_MethodHook() {
                    @Override
                    @SuppressWarnings("unchecked")
                    protected void afterHookedMethod(MethodHookParam param) {
                        Object result = param.getResult();
                        if (result instanceof Enumeration) {
                            Enumeration<NetworkInterface> original =
                                (Enumeration<NetworkInterface>) result;
                            List<NetworkInterface> filtered = new ArrayList<>();
                            while (original.hasMoreElements()) {
                                NetworkInterface ni = original.nextElement();
                                String name = ni.getName().toLowerCase();
                                if (!name.startsWith("tun") &&
                                    !name.startsWith("ppp") &&
                                    !name.startsWith("tap") &&
                                    !name.startsWith("vpn") &&
                                    !name.equals("dummy0")) {
                                    filtered.add(ni);
                                } else {
                                    XposedBridge.log(TAG + ": 过滤VPN网卡: " + name);
                                }
                            }
                            param.setResult(Collections.enumeration(filtered));
                        }
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": NetworkInterface hook失败 → " + e.getMessage());
        }

        // TYPE_VPN = 17 旧版API
        try {
            XposedHelpers.findAndHookMethod(
                ConnectivityManager.class,
                "getActiveNetworkInfo",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        Object result = param.getResult();
                        if (result instanceof NetworkInfo) {
                            NetworkInfo info = (NetworkInfo) result;
                            if (info.getType() == 17) {
                                XposedBridge.log(TAG + ": getActiveNetworkInfo TYPE_VPN → null");
                                param.setResult(null);
                            }
                        }
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": getActiveNetworkInfo hook失败 → " + e.getMessage());
        }
    }

    // ================================================================
    // 调试检测
    // ================================================================
    private void hookDebugDetection() {
        try {
            XposedHelpers.findAndHookMethod(
                android.os.Debug.class,
                "isDebuggerConnected",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        logOnce(TAG + ": [拦截] Debug.isDebuggerConnected → false");
                        param.setResult(false);
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": Debug.isDebuggerConnected hook失败 → " + e.getMessage());
        }

        try {
            XposedHelpers.findAndHookMethod(
                android.os.Debug.class,
                "waitingForDebugger",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        logOnce(TAG + ": [拦截] Debug.waitingForDebugger → false");
                        param.setResult(false);
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": Debug.waitingForDebugger hook失败 → " + e.getMessage());
        }
    }

    // ================================================================
    // Root 检测（Runtime.exec）
    // ================================================================
    private void hookRootExecDetection() {
        // Hook exec(String)
        try {
            XposedHelpers.findAndHookMethod(
                Runtime.class,
                "exec",
                String.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String cmd = (String) param.args[0];
                        if (isRootCommand(cmd)) {
                            logOnce(TAG + ": [拦截] Runtime.exec(" + cmd + ") → IOException");
                            throw new java.io.IOException("Permission denied");
                        }
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": Runtime.exec(String) hook失败 → " + e.getMessage());
        }

        // Hook exec(String[])
        try {
            XposedHelpers.findAndHookMethod(
                Runtime.class,
                "exec",
                String[].class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String[] cmds = (String[]) param.args[0];
                        if (cmds != null) {
                            for (String c : cmds) {
                                if (isRootCommand(c)) {
                                    logOnce(TAG + ": [拦截] Runtime.exec(String[]) → IOException");
                                    throw new java.io.IOException("Permission denied");
                                }
                            }
                        }
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": Runtime.exec(String[]) hook失败 → " + e.getMessage());
        }
    }

    private boolean isRootCommand(String cmd) {
        if (cmd == null) return false;
        String lower = cmd.trim().toLowerCase();
        return lower.equals("su") ||
               lower.startsWith("su ") ||
               lower.contains("which su") ||
               lower.equals("id") ||
               lower.startsWith("id ") ||
               lower.contains("/su/") ||
               lower.contains("/sbin/su") ||
               lower.contains("supersu") ||
               lower.contains("magisk");
    }

    // ================================================================
    // 系统属性检测
    // ================================================================
    private void hookSystemProperties() {
        try {
            Class<?> sysPropClass = Class.forName("android.os.SystemProperties");
            XposedHelpers.findAndHookMethod(
                sysPropClass,
                "get",
                String.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        String key = (String) param.args[0];
                        String safe = getSafePropValue(key);
                        if (safe != null) {
                            logOnce(TAG + ": [拦截] SystemProperties.get(" + key + ") → " + safe);
                            param.setResult(safe);
                        }
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": SystemProperties.get(String) hook失败 → " + e.getMessage());
        }

        try {
            Class<?> sysPropClass = Class.forName("android.os.SystemProperties");
            XposedHelpers.findAndHookMethod(
                sysPropClass,
                "get",
                String.class,
                String.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        String key = (String) param.args[0];
                        String safe = getSafePropValue(key);
                        if (safe != null) {
                            logOnce(TAG + ": [拦截] SystemProperties.get(" + key + ") → " + safe);
                            param.setResult(safe);
                        }
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": SystemProperties.get(String,String) hook失败 → " + e.getMessage());
        }
    }

    private String getSafePropValue(String key) {
        if (key == null) return null;
        switch (key) {
            case "ro.debuggable":       return "0";
            case "ro.secure":           return "1";
            case "ro.build.tags":       return "release-keys";
            case "ro.build.type":       return "user";
            case "ro.build.version.sdk": return null; // 不干预
            default:                    return null;
        }
    }

    // ================================================================
    // 包名检测（getPackageInfo）
    // ================================================================
    private void hookPackageManager() {
        try {
            Class<?> apmClass = Class.forName("android.app.ApplicationPackageManager");
            XposedHelpers.findAndHookMethod(
                apmClass,
                "getPackageInfo",
                String.class,
                int.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String pkg = (String) param.args[0];
                        if (isSensitivePkg(pkg)) {
                            logOnce(TAG + ": [拦截] PackageManager.getPackageInfo(" + pkg + ") → NameNotFoundException");
                            throw new android.content.pm.PackageManager.NameNotFoundException(pkg);
                        }
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": getPackageInfo hook失败 → " + e.getMessage());
        }
    }

    // ================================================================
    // 文件路径检测
    // ================================================================
    private void hookFileExists() {
        try {
            XposedHelpers.findAndHookMethod(
                File.class,
                "exists",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        File f = (File) param.thisObject;
                        String path = f.getAbsolutePath();
                        if (isRootPath(path)) {
                            logOnce(TAG + ": [拦截] File.exists(" + path + ") → false");
                            param.setResult(false);
                        }
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": File.exists hook失败 → " + e.getMessage());
        }
    }

    private boolean isRootPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase();
        return lower.contains("/data/adb/magisk") ||
               lower.contains("/sbin/.magisk") ||
               lower.contains("/su/bin/su") ||
               lower.contains("/system/bin/su") ||
               lower.contains("/system/xbin/su") ||
               lower.contains("/system/app/supersu") ||
               lower.contains("/system/app/superuser") ||
               lower.contains("/data/local/tmp/frida") ||
               lower.contains("/data/local/bin/su") ||
               lower.contains("/sbin/su") ||
               lower.contains("/.supersu") ||
               lower.contains("/magisk") ||
               lower.contains("xposed") ||
               lower.contains("lsposed") ||
               lower.contains("riru") ||
               lower.contains("zygisk") ||
               lower.contains("shamiko");
    }

    // ================================================================
    // Build 属性检测
    // ================================================================
    private void hookBuildFields() {
        try {
            setBuildField("TAGS", "release-keys");
            setBuildField("TYPE", "user");
            // 修正 FINGERPRINT 中的 test-keys
            try {
                Field fpField = Build.class.getField("FINGERPRINT");
                fpField.setAccessible(true);
                String fp = (String) fpField.get(null);
                if (fp != null && fp.contains("test-keys")) {
                    String safeFp = fp.replace("test-keys", "release-keys");
                    fpField.set(null, safeFp);
                    XposedBridge.log(TAG + ": [修改] Build.FINGERPRINT test-keys → release-keys");
                }
            } catch (Exception e) {
                XposedBridge.log(TAG + ": Build.FINGERPRINT 修改失败 → " + e.getMessage());
            }
        } catch (Exception e) {
            XposedBridge.log(TAG + ": Build字段修改失败 → " + e.getMessage());
        }
    }

    private void setBuildField(String fieldName, String value) {
        try {
            Field field = Build.class.getField(fieldName);
            field.setAccessible(true);
            String current = (String) field.get(null);
            field.set(null, value);
            XposedBridge.log(TAG + ": [修改] Build." + fieldName + " → " + value
                + " (原值: " + current + ")");
        } catch (Exception e) {
            XposedBridge.log(TAG + ": Build." + fieldName + " 修改失败 → " + e.getMessage());
        }
    }

    // ================================================================
    // 工具方法
    // ================================================================
    private void hookReturn(ClassLoader cl, String className,
                            String methodName, final Object returnValue) {
        hookMethod(cl, className, methodName, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                param.setResult(returnValue);
            }
        });
    }

    private void hookMethod(ClassLoader cl, String className,
                            String methodName, XC_MethodHook hook) {
        try {
            Class<?> clazz = XposedHelpers.findClass(className, cl);
            XposedBridge.hookAllMethods(clazz, methodName, hook);
            XposedBridge.log(TAG + ": Hook成功 → " + className + "." + methodName);
        } catch (XposedHelpers.ClassNotFoundError e) {
            XposedBridge.log(TAG + ": 类未找到 → " + className);
        } catch (Exception e) {
            XposedBridge.log(TAG + ": Hook失败 → " + className + "." + methodName
                + " : " + e.getMessage());
        }
    }

    private boolean isSensitivePkg(String pkg) {
        if (pkg == null) return false;
        String lower = pkg.toLowerCase();
        return lower.contains("xposed") ||
               lower.contains("lsposed") ||
               lower.contains("xhs923") ||
               lower.contains("yang.xhs") ||
               lower.contains("hidemyapplist") ||
               lower.contains("tsng.hide") ||
               lower.contains("magisk") ||
               lower.contains("shamiko") ||
               lower.contains("zygisk") ||
               lower.contains("frida") ||
               lower.contains("substrate") ||
               lower.contains("taichi") ||
               lower.contains("edxposed") ||
               lower.contains("riru") ||
               lower.contains("virtualapp") ||
               lower.contains("vxp") ||
               lower.contains("parallel") ||
               lower.contains("dualspace") ||
               lower.contains("cloneapp");
    }

    private String filterMapsInfo(String maps) {
        if (maps == null) return "";
        StringBuilder sb = new StringBuilder();
        for (String line : maps.split("\n")) {
            String lower = line.toLowerCase();
            if (!lower.contains("lsposed") &&
                !lower.contains("xposed") &&
                !lower.contains("riru") &&
                !lower.contains("zygisk") &&
                !lower.contains("magisk") &&
                !lower.contains("frida") &&
                !lower.contains("substrate") &&
                !lower.contains("xhs923") &&
                !lower.contains("shamiko") &&
                !lower.contains("edxposed")) {
                sb.append(line).append("\n");
            }
        }
        return sb.toString();
    }
}
