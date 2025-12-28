// ---------------------------------------------------------
// Project: Clickme Java Layer Bypass
// Target: com.example.clickme.MainActivity.checkPassword
// ---------------------------------------------------------

Java.perform(function() {
    console.log("[*] Starting Java Layer Hook...");

    // 1. 定位目标类
    // 你的包名是 com.example.clickme，类名是 MainActivity
    var MainActivity = Java.use("com.example.clickme.MainActivity");

    // 2. 覆盖(Overwrite)目标方法
    // implementation 是 Frida 用来替换原方法逻辑的接口
    MainActivity.checkPassword.implementation = function(input) {

        console.log(`\n[+] Intercepted checkPassword!`);
        console.log(`[+] User Input: "${input}"`);

        // 3. (可选) 执行原始逻辑
        // 如果你想看原本C++会返回什么，可以这样调用：
        var originalResult = this.checkPassword(input);
        console.log(`[+] Original Native Result: ${originalResult}`);

        // 4. 实施欺骗
        // 我们不关心原始结果，直接返回 true
        console.log("[!] BYPASS: Forcing return value to TRUE (Success)");

        return true;
    };

    console.log("[*] Hook setup complete. Click the button now.");
});