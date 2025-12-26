package com.example.clickme

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast

class MainActivity : AppCompatActivity() {

    // JNI函数声明
    external fun checkPassword(input: String): Boolean

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val editText = findViewById<EditText>(R.id.editText)
        val button = findViewById<Button>(R.id.button)

        button.setOnClickListener {
            val input = editText.text.toString()
            if (input.isNotEmpty()) {
                val result = checkPassword(input)
                val message = if (result) "密码正确!" else "密码错误!"
                Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "请输入密码", Toast.LENGTH_SHORT).show()
            }
        }
    }

    companion object {
        // 加载本地库
        init {
            System.loadLibrary("native-lib")
        }
    }
}
