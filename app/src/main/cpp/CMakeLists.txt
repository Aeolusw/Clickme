cmake_minimum_required(VERSION 3.22.1)

# 设置项目名称
project("native-lib")

# 创建库
add_library(native-lib SHARED
    native-lib.cpp)

# 查找log库
find_library(log-lib log)

# 链接库
target_link_libraries(native-lib
    android
    ${log-lib})
