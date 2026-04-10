package com.example.xhshook;

import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;

import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class XhsAntiDetectHook implements IXposedHookLoadPackage {

    private static final String TAG = "XhsHook";
    private static final String TARGET_PKG = "com.xingin.xhs";

    private final AtomicBoolean vpnLoggedOnce = new AtomicBoolean(false);

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!TARGET_PKG.equals(lpparam.packageName)) return;
        XposedBridge.log(TAG + ": XHS已加载，开始注入Hook");

        hookCallJavaJniTest(lpparam.classLoader);
        hookNativeGatherTest(lpparam.classLoader);
        hookBasicJniTest(lpparam.classLoader);
        hookVpnDetection(lpparam.classLoader);
    }

    // ================================================================
    // CallJavaJniTest
    // ================================================================
    private void hookCallJavaJniTest(ClassLoader cl) {
        final String CLASS = "com.xingin.a.a.f.jni.CallJavaJniTest";
        Class<?> clazz;
        try {
            clazz = XposedHelpers.findClass(CLASS, cl);
        } catch (XposedHelpers.ClassNotFoundError e) {
            XposedBridge.log(TAG + ": [跳过] 类不存在于当前版本 → " + CLASS);
            return;
        }

        // Xposed 检测
        hookClassReturn(clazz, "existXposed", false);
        hookClassReturn(clazz, "getCheckingXposedResult", 0);
        hookClassReturn(clazz, "getCheckingVirtualAppResult", 0);

        // 无障碍检测
        hookClassReturn(clazz, "getAccessibilityStatus", 0);
        hookClassReturn(clazz, "getEnabledAccessibilityServices", "");

        // 进程枚举
        hookClassReturn(clazz, "getRunningProcessListByCommand", new ArrayList<String>());
        hookClassReturn(clazz, "getRunningProcessListBySdkApi", new ArrayList<String>());

        // 隐藏应用列表
        hookClassReturn(clazz, "getSecretAppList", new ArrayList<String>());

        // 开发者选项
        hookClassReturn(clazz, "devOpenedCount", 0);

        // 安装列表过滤
        hookClassMethod(clazz, "getInstallApps", new XC_MethodHook() {
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
        Class<?> clazz;
        try {
            clazz = XposedHelpers.findClass(CLASS, cl);
        } catch (XposedHelpers.ClassNotFoundError e) {
            XposedBridge.log(TAG + ": [跳过] 类不存在于当前版本 → " + CLASS);
            return;
        }

        hookClassReturn(clazz, "isRoot", false);
        hookClassReturn(clazz, "isPtrace", false);

        hookClassMethod(clazz, "mapsInfo", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                Object result = param.getResult();
                if (result instanceof String) {
                    param.setResult(filterMapsInfo((String) result));
                }
            }
        });

        hookClassMethod(clazz, "getProcessName", new XC_MethodHook() {
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
        Class<?> clazz;
        try {
            clazz = XposedHelpers.findClass(CLASS, cl);
        } catch (XposedHelpers.ClassNotFoundError e) {
            XposedBridge.log(TAG + ": [跳过] 类不存在于当前版本 → " + CLASS);
            return;
        }

        hookClassReturn(clazz, "isDebugAble", false);
        hookClassReturn(clazz, "getBuildIsEmulator", false);
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
                            if (vpnLoggedOnce.compareAndSet(false, true)) {
                                XposedBridge.log(TAG + ": hasTransport(VPN) 拦截 → false");
                            }
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
    // 工具方法
    // ================================================================

    /** 对已解析的 clazz 执行单次类查找后的 hookReturn，避免重复 findClass */
    private void hookClassReturn(Class<?> clazz,
                                 String methodName, final Object returnValue) {
        hookClassMethod(clazz, methodName, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                param.setResult(returnValue);
            }
        });
    }

    /** 对已解析的 clazz 执行 hook，不再重复调用 findClass */
    private void hookClassMethod(Class<?> clazz,
                                 String methodName, XC_MethodHook hook) {
        try {
            XposedBridge.hookAllMethods(clazz, methodName, hook);
            XposedBridge.log(TAG + ": Hook成功 → " + clazz.getName() + "." + methodName);
        } catch (Exception e) {
            XposedBridge.log(TAG + ": Hook失败 → " + clazz.getName() + "." + methodName
                + " : " + e.getMessage());
        }
    }

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
