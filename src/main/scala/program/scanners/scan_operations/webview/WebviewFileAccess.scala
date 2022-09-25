package program.scanners.scan_operations.webview

import program.scanners.scan_operations.ScanOperation
import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import program.scanners.scan_operations.SecurityWarning
import org.opalj.br.ObjectType
import org.opalj.br.instructions.LoadString

object WebviewFileAccess extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val webSettingsType = ObjectType("android/webkit/WebSettings")
    if (methodCall.declaringClass == webSettingsType && methodCall.name == "setAllowFileAccess") {
      val operands = interpretation.operandsArray(pc)
      val argumentOrigin = interpretation.domain.origins(operands(0))
      print(argumentOrigin)
    }
    return false
  }
  
  
  override def json = SecurityWarning(
    """WebView File System Access is enabled. An attacker able to inject script into a WebView, could exploit the opportunity to access local resources.""",
    "WARNING",
    "cwe-73",
    "m7",
    "platform-6",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md/#testing-webview-protocol-handlers-mstg-platform-6"
  )

  override def name = "Webview File Access"
}

/*
patterns:
      - pattern-either:
          - pattern: |
              $WB.setAllowFileAccess(true);
*/