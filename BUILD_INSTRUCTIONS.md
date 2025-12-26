# Clickme Android 应用构建说明

这是一个使用Kotlin和C++的Android应用，包含一个简单的密码检查功能。

## 项目结构

```
Clickme/
├── settings.gradle.kts          # Gradle设置
├── build.gradle.kts             # 项目级Gradle配置
├── app/
│   ├── build.gradle.kts         # 模块级Gradle配置
│   ├── src/main/
│   │   ├── AndroidManifest.xml  # Android清单文件
│   │   ├── java/com/example/clickme/
│   │   │   └── MainActivity.kt  # Kotlin主活动
│   │   ├── cpp/
│   │   │   ├── CMakeLists.txt   # CMake配置
│   │   │   └── native-lib.cpp   # C++ JNI实现
│   │   └── res/
│   │       ├── layout/          # 布局文件
│   │       └── values/          # 字符串资源
│   └── BUILD_INSTRUCTIONS.md    # 此文件
```

## 构建要求

1. **Android Studio** 或 **VS Code** 配合 Android SDK
2. **Android SDK** (API 34)
3. **Android NDK** (用于C++编译)
4. **Gradle**

## 构建步骤

### 选项1: 使用Gradle Wrapper (推荐)

#### 1. 初始化Gradle Wrapper

首次构建前，Gradle Wrapper会自动下载所需的Gradle版本。

#### 2. 使用命令行构建

在项目根目录 (`Clickme/`) 中运行:

```bash
# Windows
.\gradlew.bat assembleDebug

# Linux/Mac
./gradlew assembleDebug
```

#### 3. 安装到设备/模拟器

```bash
# 连接Android设备或启动模拟器
.\gradlew.bat installDebug
```

### 选项2: 使用已安装的Gradle

如果Gradle Wrapper无法工作（例如gradle-wrapper.jar损坏或下载失败），可以使用系统已安装的Gradle：

1. 确保已安装Gradle 8.4或兼容版本
2. 在项目根目录运行:

```bash
# 使用gradle命令
gradle assembleDebug

# 安装到设备
gradle installDebug
```

### 运行应用

安装后，应用将自动启动。或者可以在设备上找到 "Clickme" 应用图标。

## 功能说明

1. 应用界面有一个文本输入框和一个按钮
2. 在文本框中输入密码
3. 点击 "Click Me" 按钮
4. 应用通过JNI调用C++函数检查密码是否为 "123"
5. 显示Toast消息提示密码正确或错误

## JNI函数说明

- `checkPassword(input: String): Boolean` - 在C++中实现
- 如果输入是 "123"，返回 `true`，否则返回 `false`

## 故障排除

1. **gradlew.bat无法工作**: 如果遇到"找不到或无法加载主类 org.gradle.wrapper.GradleWrapperMain"错误，说明gradle-wrapper.jar文件可能损坏或缺失。解决方案：
   - 使用选项2：使用已安装的Gradle
   - 手动下载gradle-wrapper.jar：从[Gradle官网](https://services.gradle.org/distributions/)下载gradle-8.4-bin.zip，解压后找到`gradle-8.4/lib/gradle-wrapper-8.4.jar`，复制到`gradle/wrapper/gradle-wrapper.jar`

2. **C++头文件错误**: 如果在VS Code中看到jni.h错误，请确保安装了Android NDK，并配置了正确的include路径。

3. **构建失败**: 检查是否安装了正确的Android SDK版本 (API 34)。

4. **JNI链接错误**: 确保CMakeLists.txt配置正确，且native-lib.cpp中的函数签名与Kotlin中的声明匹配。

5. **运行崩溃**: 确保设备/模拟器支持minSdk (24) 或更高版本。

6. **Gradle下载慢**: 如果gradlew.bat下载Gradle速度慢，可以手动下载distributionUrl中的Gradle版本，放到gradle/wrapper/dists目录下。

## 修改密码逻辑

要修改密码检查逻辑，编辑 `app/src/main/cpp/native-lib.cpp` 中的以下部分：

```cpp
// 检查密码是否为"123"
std::string password(inputStr);
bool result = (password == "123");  // 修改这里的"123"为其他值
```

## 注意事项

- 这是一个演示项目，实际应用中不应硬编码密码
- 生产环境应使用安全的密码存储和验证方法
- JNI调用有一定的性能开销，应谨慎使用
