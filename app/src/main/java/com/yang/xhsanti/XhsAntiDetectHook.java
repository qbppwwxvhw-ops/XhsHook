package com.yang.xhsanti;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.net.NetworkCapabilities;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;

import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * 小红书安全检测绕过（独立LSP模块版）
 *
 * 覆盖点：
 *  1. JNI风控类 (libxyasf.so)：existXposed / isRoot / isDebugAble 等
 *  2. com.xingin.u.p.c 数据采集类：existXposed / getCheckingXposedResult 等
 *  3. APK完整性锁定（签名/CRC/JS指纹）
 *  4. 设备指纹锁定（FingerPrintJni）
 *  5. ClassLoader.loadClass 拦截 Xposed 类名探测
 *  6. PackageManager API 过滤敏感包名
 *  7. USB调试 / 开发者选项隐藏
 *  8. Debug调试器检测绕过
 *  9. VPN检测绕过
 * 10. /proc/self/maps 过滤 hook 框架路径
 */
public class XhsAntiDetectHook {

    private static final String TAG = "XhsAnti";

    public static void init(ClassLoader cl) {
        XposedBridge.log(TAG + ": 开始注入防检测Hook");

        // JNI层风控（libxyasf.so 符号）
        hookCallJavaJniTest(cl);
        hookNativeGatherTest(cl);
        hookBasicJniTest(cl);
        // Java层数据采集类（com.xingin.u.p.c）
        hookDataCollectionClass(cl);
        // APK完整性（签名/CRC/JS指纹）锁定首次值，防注入后漂移
        hookApkIntegrity(cl);
        // 设备指纹锁定
        hookFingerprint(cl);
        // ClassLoader探测Xposed类名
        hookClassLoaderXposedCheck(cl);
        // PackageManager应用列表
        hookPackageManagerApps();
        // 系统Settings
        hookUsbDebugging();
        hookDebugDetection(cl);
        hookVpnDetection();
    }

    // ================================================================
    // 1. CallJavaJniTest — Xposed/环境/进程/安装列表检测
    // ================================================================
    private static void hookCallJavaJniTest(ClassLoader cl) {
        final String CLASS = "com.xingin.a.a.f.jni.CallJavaJniTest";

        hookReturnAfter(cl, CLASS, "existXposed", false);
        hookReturnAfter(cl, CLASS, "getCheckingXposedResult", 0);
        hookReturnAfter(cl, CLASS, "getCheckingVirtualAppResult", 0);
        hookReturnAfter(cl, CLASS, "getAccessibilityStatus", 0);
        hookReturnAfter(cl, CLASS, "getEnabledAccessibilityServices", "");
        hookReturnAfter(cl, CLASS, "getRunningProcessListByCommand", new ArrayList<String>());
        hookReturnAfter(cl, CLASS, "getRunningProcessListBySdkApi", new ArrayList<String>());
        hookReturnAfter(cl, CLASS, "getSecretAppList", new ArrayList<String>());
        hookReturnAfter(cl, CLASS, "devOpenedCount", 0);

        hookMethod(cl, CLASS, "getInstallApps", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                Object result = param.getResult();
                if (result instanceof List) {
                    List<String> filtered = new ArrayList<>();
                    for (Object item : (List<?>) result) {
                        if (item instanceof String && !isSensitivePkg((String) item)) {
                            filtered.add((String) item);
                        }
                    }
                    param.setResult(filtered);
                }
            }
        });
    }

    // ================================================================
    // 2. NativeGatherTest — Root / ptrace / maps / 进程名
    // ================================================================
    private static void hookNativeGatherTest(ClassLoader cl) {
        final String CLASS = "com.xingin.a.a.f.jni.NativeGatherTest";

        hookReturnAfter(cl, CLASS, "isRoot", false);
        hookReturnAfter(cl, CLASS, "isPtrace", false);

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
    // 3. BasicJniTest — 模拟器 / 可调试标志
    // ================================================================
    private static void hookBasicJniTest(ClassLoader cl) {
        final String CLASS = "com.xingin.a.a.f.jni.BasicJniTest";
        hookReturnAfter(cl, CLASS, "isDebugAble", false);
        hookReturnAfter(cl, CLASS, "getBuildIsEmulator", false);
    }

    // ================================================================
    // 4. com.xingin.u.p.c — Java层数据采集包装类
    // ================================================================
    private static void hookDataCollectionClass(ClassLoader cl) {
        final String CLASS = "com.xingin.u.p.c";

        hookReturnAfter(cl, CLASS, "existXposed", false);
        hookReturnAfter(cl, CLASS, "getCheckingXposedResult", 0);
        hookReturnAfter(cl, CLASS, "getCheckingVirtualAppResult", 0);
        hookReturnAfter(cl, CLASS, "getAccessibilityStatus", 0);
        hookReturnAfter(cl, CLASS, "getEnabledAccessibilityServices", "");
        hookReturnAfter(cl, CLASS, "devOpenedCount", 0);
        hookReturnAfter(cl, CLASS, "getSecretAppList", "");

        XC_MethodHook filterStringListHook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                Object result = param.getResult();
                if (result instanceof String) {
                    param.setResult(filterPkgString((String) result, ";"));
                }
            }
        };
        hookMethod(cl, CLASS, "getInstallApps", filterStringListHook);
        hookMethod(cl, CLASS, "getRunningProcessListByCommand", filterStringListHook);
        hookMethod(cl, CLASS, "getRunningProcessListBySdkApi", filterStringListHook);
    }

    // ================================================================
    // 4.1 APK完整性锁定
    //
    // 策略：第一次调用时缓存真实返回值，后续始终返回缓存值，确保一致性。
    // ================================================================
    private static void hookApkIntegrity(ClassLoader cl) {
        final String CLASS = "com.xingin.u.p.c";

        hookMethod(cl, CLASS, "getApkSignature", new XC_MethodHook() {
            private volatile Object cached = null;
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (cached == null && param.getResult() != null) {
                    cached = param.getResult();
                    XposedBridge.log(TAG + ": 缓存 getApkSignature");
                } else if (cached != null) {
                    param.setResult(cached);
                }
            }
        });

        hookMethod(cl, CLASS, "getApkCRC", new XC_MethodHook() {
            private volatile Object cached = null;
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (cached == null && param.getResult() != null) {
                    cached = param.getResult();
                    XposedBridge.log(TAG + ": 缓存 getApkCRC");
                } else if (cached != null) {
                    param.setResult(cached);
                }
            }
        });

        hookMethod(cl, CLASS, "getJsFingerprint", new XC_MethodHook() {
            private volatile Object cached = null;
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (cached == null && param.getResult() != null) {
                    cached = param.getResult();
                    XposedBridge.log(TAG + ": 缓存 getJsFingerprint");
                } else if (cached != null) {
                    param.setResult(cached);
                }
            }
        });
    }

    // ================================================================
    // 4.2 设备指纹锁定
    //
    // 策略：缓存第一次Native返回的真实指纹值，防止多次调用结果不一致。
    // ================================================================
    private static void hookFingerprint(ClassLoader cl) {
        hookMethod(cl, "com.xingin.a.a.f.FingerPrintJni", "getFingerPrint", new XC_MethodHook() {
            private volatile String cached = null;
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (cached == null && param.getResult() instanceof String) {
                    cached = (String) param.getResult();
                    XposedBridge.log(TAG + ": 缓存 FingerPrint (len=" + cached.length() + ")");
                } else if (cached != null) {
                    param.setResult(cached);
                }
            }
        });
    }

    // ================================================================
    // 5. ClassLoader.loadClass — 拦截 Xposed 类名探测
    // ================================================================
    private static void hookClassLoaderXposedCheck(ClassLoader cl) {
        final String[] SENSITIVE_CLASSES = {
            "de.robv.android.xposed.XposedHelpers",
            "de.robv.android.xposed.XposedBridge",
            "de.robv.android.xposed.XC_MethodHook",
            "de.robv.android.xposed.XC_MethodReplacement",
        };

        XC_MethodHook loadClassHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                String className = (String) param.args[0];
                if (className == null) return;
                for (String s : SENSITIVE_CLASSES) {
                    if (s.equals(className)) {
                        param.setThrowable(new ClassNotFoundException("Class not found: " + className));
                        return;
                    }
                }
            }
        };

        try {
            XposedHelpers.findAndHookMethod(ClassLoader.class, "loadClass",
                String.class, loadClassHook);
        } catch (Exception e) {
            XposedBridge.log(TAG + ": ClassLoader.loadClass hook失败: " + e.getMessage());
        }

        try {
            XposedHelpers.findAndHookMethod(ClassLoader.class, "loadClass",
                String.class, boolean.class, loadClassHook);
        } catch (Exception ignored) {}

        hookMethod(cl, "hka.c", "a", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                param.setResult(false);
            }
        });
    }

    // ================================================================
    // 6. PackageManager — 应用列表 API 过滤
    // ================================================================
    private static void hookPackageManagerApps() {

        try {
            XposedHelpers.findAndHookMethod(
                android.content.pm.PackageManager.class,
                "getInstalledPackages",
                int.class,
                new XC_MethodHook() {
                    @Override
                    @SuppressWarnings("unchecked")
                    protected void afterHookedMethod(MethodHookParam param) {
                        List<PackageInfo> pkgList = (List<PackageInfo>) param.getResult();
                        if (pkgList == null) return;
                        List<PackageInfo> filtered = new ArrayList<>();
                        for (PackageInfo pi : pkgList) {
                            if (pi != null && !isSensitivePkg(pi.packageName)) filtered.add(pi);
                        }
                        param.setResult(filtered);
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": getInstalledPackages hook失败: " + e.getMessage());
        }

        try {
            XposedHelpers.findAndHookMethod(
                android.content.pm.PackageManager.class,
                "getInstalledApplications",
                int.class,
                new XC_MethodHook() {
                    @Override
                    @SuppressWarnings("unchecked")
                    protected void afterHookedMethod(MethodHookParam param) {
                        List<ApplicationInfo> appList = (List<ApplicationInfo>) param.getResult();
                        if (appList == null) return;
                        List<ApplicationInfo> filtered = new ArrayList<>();
                        for (ApplicationInfo ai : appList) {
                            if (ai != null && !isSensitivePkg(ai.packageName)) filtered.add(ai);
                        }
                        param.setResult(filtered);
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": getInstalledApplications hook失败: " + e.getMessage());
        }

        try {
            XposedHelpers.findAndHookMethod(
                android.content.pm.PackageManager.class,
                "getPackageInfo",
                String.class,
                int.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String pkgName = (String) param.args[0];
                        if (isSensitivePkg(pkgName)) {
                            param.setThrowable(
                                new android.content.pm.PackageManager.NameNotFoundException(pkgName));
                        }
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": getPackageInfo hook失败: " + e.getMessage());
        }
    }

    // ================================================================
    // 7. USB调试 + 开发者选项隐藏
    // ================================================================
    private static void hookUsbDebugging() {

        try {
            XposedHelpers.findAndHookMethod(
                android.provider.Settings.Secure.class, "getInt",
                android.content.ContentResolver.class, String.class, int.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        String key = (String) param.args[1];
                        if ("adb_enabled".equals(key)) {
                            param.setResult(0);
                        } else if ("accessibility_enabled".equals(key)) {
                            param.setResult(0);
                        }
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": Settings.Secure.getInt hook失败: " + e.getMessage());
        }

        try {
            XposedHelpers.findAndHookMethod(
                android.provider.Settings.Secure.class, "getInt",
                android.content.ContentResolver.class, String.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        String key = (String) param.args[1];
                        if ("adb_enabled".equals(key)) {
                            param.setResult(0);
                        }
                    }
                }
            );
        } catch (Exception ignored) {}

        try {
            XposedHelpers.findAndHookMethod(
                android.provider.Settings.Global.class, "getInt",
                android.content.ContentResolver.class, String.class, int.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        String key = (String) param.args[1];
                        if ("adb_enabled".equals(key) ||
                            "development_settings_enabled".equals(key) ||
                            "adb_wifi_enabled".equals(key)) {
                            param.setResult(0);
                        }
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": Settings.Global.getInt hook失败: " + e.getMessage());
        }

        try {
            XposedHelpers.findAndHookMethod(
                android.provider.Settings.Secure.class, "getString",
                android.content.ContentResolver.class, String.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        String key = (String) param.args[1];
                        if ("adb_enabled".equals(key)) {
                            param.setResult("0");
                        } else if ("enabled_accessibility_services".equals(key)) {
                            param.setResult("");
                        }
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": Settings.Secure.getString hook失败: " + e.getMessage());
        }

    }

    // ================================================================
    // 8. Debug调试器检测
    // ================================================================
    private static void hookDebugDetection(ClassLoader cl) {

        try {
            XposedHelpers.findAndHookMethod(android.os.Debug.class, "isDebuggerConnected",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        param.setResult(false);
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": isDebuggerConnected hook失败: " + e.getMessage());
        }

        try {
            XposedHelpers.findAndHookMethod(android.os.Debug.class, "waitingForDebugger",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        param.setResult(false);
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": waitingForDebugger hook失败: " + e.getMessage());
        }

        try {
            XposedHelpers.findAndHookMethod(android.content.pm.ApplicationInfo.class, "isDebuggable",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        param.setResult(false);
                    }
                }
            );
        } catch (Exception ignored) {}
    }

    // ================================================================
    // 9. VPN 检测绕过
    // ================================================================
    private static void hookVpnDetection() {

        try {
            XposedHelpers.findAndHookMethod(NetworkCapabilities.class, "hasTransport", int.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        if ((int) param.args[0] == 4) param.setResult(false); // TRANSPORT_VPN
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": hasTransport hook失败: " + e.getMessage());
        }

        try {
            XposedHelpers.findAndHookMethod(NetworkCapabilities.class, "hasCapability", int.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        if ((int) param.args[0] == 15) param.setResult(true); // NET_CAPABILITY_NOT_VPN
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": hasCapability hook失败: " + e.getMessage());
        }

        try {
            XposedHelpers.findAndHookMethod(NetworkInterface.class, "getNetworkInterfaces",
                new XC_MethodHook() {
                    @Override
                    @SuppressWarnings("unchecked")
                    protected void afterHookedMethod(MethodHookParam param) {
                        Object result = param.getResult();
                        if (!(result instanceof Enumeration)) return;
                        Enumeration<NetworkInterface> original = (Enumeration<NetworkInterface>) result;
                        List<NetworkInterface> filtered = new ArrayList<>();
                        while (original.hasMoreElements()) {
                            NetworkInterface ni = original.nextElement();
                            String name = ni.getName().toLowerCase();
                            if (!name.startsWith("tun") && !name.startsWith("ppp") &&
                                !name.startsWith("tap") && !name.startsWith("vpn") &&
                                !name.equals("dummy0")) {
                                filtered.add(ni);
                            }
                        }
                        param.setResult(Collections.enumeration(filtered));
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": NetworkInterface hook失败: " + e.getMessage());
        }

        try {
            XposedHelpers.findAndHookMethod(ConnectivityManager.class, "getActiveNetworkInfo",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        Object result = param.getResult();
                        if (result instanceof NetworkInfo && ((NetworkInfo) result).getType() == 17) {
                            param.setResult(null); // TYPE_VPN
                        }
                    }
                }
            );
        } catch (Exception e) {
            XposedBridge.log(TAG + ": getActiveNetworkInfo hook失败: " + e.getMessage());
        }
    }

    // ================================================================
    // 工具方法
    // ================================================================

    private static void hookReturnAfter(ClassLoader cl, String className,
                                        String methodName, final Object returnValue) {
        hookMethod(cl, className, methodName, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                param.setResult(returnValue);
            }
        });
    }

    private static void hookMethod(ClassLoader cl, String className,
                                   String methodName, XC_MethodHook hook) {
        try {
            Class<?> clazz = XposedHelpers.findClass(className, cl);
            XposedBridge.hookAllMethods(clazz, methodName, hook);
            XposedBridge.log(TAG + ": ✓ " + className + "." + methodName);
        } catch (XposedHelpers.ClassNotFoundError e) {
            XposedBridge.log(TAG + ": 类未找到(运行时可能正常) → " + className);
        } catch (Exception e) {
            XposedBridge.log(TAG + ": Hook失败 → " + className + "." + methodName + ": " + e.getMessage());
        }
    }

    private static String filterPkgString(String input, String delimiter) {
        if (input == null || input.isEmpty()) return input;
        String[] parts = input.split(delimiter);
        StringBuilder sb = new StringBuilder();
        for (String part : parts) {
            if (!isSensitivePkg(part)) {
                if (sb.length() > 0) sb.append(delimiter);
                sb.append(part);
            }
        }
        return sb.toString();
    }

    static boolean isSensitivePkg(String pkg) {
        if (pkg == null || pkg.isEmpty()) return false;
        String lower = pkg.toLowerCase();
        return lower.contains("xposed") ||
               lower.contains("lsposed") ||
               lower.contains("edxposed") ||
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
               lower.contains("riru") ||
               lower.contains("virtualapp") ||
               lower.contains("vxp") ||
               lower.contains("parallel") ||
               lower.contains("dualspace") ||
               lower.contains("cloneapp") ||
               lower.contains("appclone") ||
               lower.contains("sandvxposed");
    }

    private static String filterMapsInfo(String maps) {
        if (maps == null) return "";
        StringBuilder sb = new StringBuilder();
        for (String line : maps.split("\n")) {
            String lower = line.toLowerCase();
            if (!lower.contains("lsposed") && !lower.contains("xposed") &&
                !lower.contains("riru") && !lower.contains("zygisk") &&
                !lower.contains("magisk") && !lower.contains("frida") &&
                !lower.contains("substrate") && !lower.contains("xhs923") &&
                !lower.contains("shamiko") && !lower.contains("edxposed")) {
                sb.append(line).append("\n");
            }
        }
        return sb.toString();
    }

    /**
     * 过滤无障碍服务列表，移除注入框架相关的服务条目。
     * Android格式："pkg1/cls1:pkg2/cls2"，用冒号分隔。
     * 只移除包名属于敏感包的条目，保留TalkBack等合法服务。
     */
    private static String filterAccessibilityServices(String services) {
        if (services == null || services.isEmpty()) return services;
        StringBuilder sb = new StringBuilder();
        for (String entry : services.split(":")) {
            String trimmed = entry.trim();
            if (trimmed.isEmpty()) continue;
            String pkg = trimmed.contains("/") ? trimmed.substring(0, trimmed.indexOf('/')) : trimmed;
            if (!isSensitivePkg(pkg)) {
                if (sb.length() > 0) sb.append(":");
                sb.append(trimmed);
            }
        }
        return sb.toString();
    }
}
