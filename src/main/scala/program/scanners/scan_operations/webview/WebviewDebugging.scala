package program.scanners.scan_operations.webview

import program.scanners.scan_operations.ScanOperation
import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import program.scanners.scan_operations.SecurityWarning
import org.opalj.br.ObjectType
import org.opalj.br.instructions.LoadString

object WebviewDebugging extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val webViewType = ObjectType("android/webkit/WebView")
    if (methodCall.declaringClass == webViewType && methodCall.name == "setWebContentsDebuggingEnabled") {
      val operands = interpretation.operandsArray(pc)
      val firstArgumentOrigin = interpretation.domain.origins(operands(0))
      //if (operands(0))

    }
    
    return false
  }
  
  override def json = SecurityWarning(
    """Remote WebView debugging is enabled. This allows an attacker with
      debugging access to interact with the webview and steal or corrupt data.""",
    "ERROR",
    "cwe-489",
    "m1",
    "resilience-2",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md#testing-anti-debugging-detection-mstg-resilience-2"
  )

  override def name = "Webview Debugging"
}