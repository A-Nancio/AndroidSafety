package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import org.opalj.br.ObjectType

object WebviewJavascriptInterface extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val webviewType = ObjectType("android/webkit/WebView")
    return methodCall.declaringClass == webviewType && methodCall.name == "addJavaScriptInterface"
  }
  
  
  override def json = SecurityWarning(
    """Ensure that javascript interface is implemented securely.
      Execution of user controlled code in WebView is a 
      critical Security issue.""",
    "WARNING",
    "cwe-749",
    "m1",
    "platform-7",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#determining-whether-java-objects-are-exposed-through-webviews-mstg-platform-7"
  )

  override def name = "Webview Javarscript Interface"
}

/*
patterns:
      - pattern-either:
          - pattern: |
              addJavascriptInterface(...)
          - pattern: |
              $W.addJavascriptInterface(...)
*/