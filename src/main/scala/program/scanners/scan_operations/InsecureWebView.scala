package program.scanners.scan_operations

import org.opalj.br.instructions.FieldAccess
import org.opalj.br.instructions.MethodInvocationInstruction

object InsecureWebView extends ScanOperation {
    override def execute(instruction: MethodInvocationInstruction): Boolean = {
        val declaringClass = instruction.declaringClass.toJava
        val boolResult = (declaringClass == "android.webkit.WebSettings" &&
            instruction.name == "setJavaScriptEnabled") ||
            (declaringClass == "android.webkit.WebView" &&
            instruction.name == "addJavascriptInterface")
        return boolResult
    }
    
    def json: SecurityWarning = {
        return SecurityWarning(
            "Insecure WebView Implementation. Execution of user controlled code in WebView is a critical Security Hole.",
            "warning",
            Array(
                "CWE-749: Exposed Dangerous Method or Function",
                "OWASP Top 10: M1: Improper Platform Usage",
                "OWASP MASVS: MSTG-PLATFORM-7"
            ),
            results
        )
    }

    def name: String = "Insecure WebView Implementation"
}
