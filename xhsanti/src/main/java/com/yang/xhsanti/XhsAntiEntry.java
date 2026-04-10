package com.yang.xhsanti;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Xposed 模块入口类。
 * 仅在小红书 (com.xingin.xhs) 加载时激活 Hook。
 */
public class XhsAntiEntry implements IXposedHookLoadPackage {

    private static final String TARGET_PKG = "com.xingin.xhs";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!TARGET_PKG.equals(lpparam.packageName)) return;
        XhsAntiDetectHook.init(lpparam.classLoader);
    }
}
