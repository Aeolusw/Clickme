// ---------------------------------------------------------
// Project: Clickme Security Bypass
// Target: libnative-lib.so -> Java_com_example_clickme_MainActivity_checkPassword
// Author: Future Game Security Engineer
// ---------------------------------------------------------

function main() {
    console.log("[*] Waiting for libnative-lib.so to load...");

    // 1. 确保库已经加载。游戏通常在启动时加载，但有时候是懒加载。
    // 这里我们使用简单的轮询或者直接假设App已运行并加载了库。
    // 在实际游戏逆向中，通常 Hook 'dlopen' 或 'android_dlopen_ext' 来监听加载。

    const libName = "libnative-lib.so";

    // C++ 代码中的 JNI 导出函数名 (从你提供的 native-lib.cpp 可知)
    // 格式通常是: Java_包名_类名_方法名 (点号换成下划线)
    const funcName = "Java_com_example_clickme_MainActivity_checkPassword";

    // 获取模块基址，确认库是否加载
    const module = Process.findModuleByName(libName);

    if (module == null) {
        console.log("[-] Library not found. Is the app running and button clicked?");
        return;
    }

    console.log(`[+] Found ${libName} at: ${module.base}`);

    // 2. 获取目标函数的内存地址
    // [Difference Explained]:
    // Module.findExportByName(lib, name): 快速查找，底层通过 hash 表或 bloom filter 查找导出表。
    // module.enumerateExports(): 暴力枚举所有导出符号。
    // 为什么用 enumerateExports？因为有时候符号名被 C++ Name Mangling (名称修饰) 修改了，
    // 或者 findExportByName 返回 null (Frida bug 或 library 加载状态问题)。
    // 作为一个安全工程师，"看见具体的列表" 比 "不管用的黑盒函数" 更可靠。

    let funcPtr = null;
    const exports = module.enumerateExports();

    for (const exp of exports) {
        if (exp.name.indexOf("checkPassword") !== -1) {
            console.log(`[+] Finding candidate: ${exp.name} @ ${exp.address}`);
            // 精确匹配防止误报
            if (exp.name === funcName) {
                funcPtr = exp.address;
                break;
            }
        }
    }

    if (funcPtr == null) {
        console.log(`[-] Could not find export: ${funcName}`);
        console.log("[-] Dumping top 5 exports for debugging:");
        exports.slice(0, 5).forEach(e => console.log(`    ${e.name}`));
        return;
    }

    console.log(`[+] Hooking ${funcName} at: ${funcPtr}`);

    // [Interview Trap]: 
    // Q: Does dlsym() always find the function?
    // A: No. Only "dynamic symbols" (.dynsym) are visible to dlsym/Frida.
    // If the function is static or "hidden visibility", it won't be in the export table.
    // You'd need to pattern scan (sigscan) or calculate offset from base address.

    // 3. 实施 Interceptor Hook
    Interceptor.attach(funcPtr, {
        // onEnter: 函数进入时调用
        onEnter: function (args) {
            // args[0] 是 JNIEnv*, args[1] 是 jobject (this), args[2] 是 jstring (input)

            // [Interview Tip]: 在这里我们演示如何读取参数，但不修改它
            // 如果要修改输入字符串，比较麻烦，因为是 jstring，需要调用 JNI Env 函数转换
            console.log("[*] Function called.");

            // 简单的堆栈回溯，查看是谁调用了这个函数 (可选)
            // console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n"));
        },

        // onLeave: 函数即将返回时调用，retval 是返回值
        onLeave: function (retval) {
            console.log(`[*] Original Return Value: ${retval}`);

            // 4. 修改返回值
            // JNI 中 jboolean 本质是 unsigned char (8 bit)，1 为 true，0 为 false
            if (retval.toInt32() === 0) {
                console.log("[!] Password was wrong. PATCHING return value to TRUE!");
                retval.replace(1); // 强制替换为 1 (True)
            }
        }
    });
}

// 确保在 Java 虚拟机环境就绪后执行
Java.perform(function () {
    main();
});