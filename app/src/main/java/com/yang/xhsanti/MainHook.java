package com.yang.xhsanti;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class MainHook implements IXposedHookLoadPackage {

    private static final String TAG = "XhsAnti";
    private static final String TARGET_PKG = "com.xingin.xhs";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!TARGET_PKG.equals(lpparam.packageName)) return;
        XposedBridge.log(TAG + ": XHS已加载，开始注入Hook");
        XhsAntiDetectHook.init(lpparam.classLoader);
    }
}
