#include <jni.h>
#include <string>

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_clickme_MainActivity_checkPassword(
        JNIEnv* env,
        jobject /* this */,
        jstring input) {

    // 将Java字符串转换为C++字符串
    const char* inputStr = env->GetStringUTFChars(input, nullptr);
    if (inputStr == nullptr) {
        return false;
    }

    // 检查密码是否为"123"
    std::string password(inputStr);
    bool result = (password == "222");

    // 释放字符串
    env->ReleaseStringUTFChars(input, inputStr);

    return result;
}
