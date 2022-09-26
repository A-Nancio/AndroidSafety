package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import org.opalj.br.ObjectType

object WebviewIgnoreSslErrors extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    return false
  }
  
  
  override def json = SecurityWarning(
    """Insecure WebView Implementation. WebView ignores SSL Certificate errors and accept any SSL Certificate. This application is vulnerable to MITM attacks.""",
    "ERROR",
    "cwe-295",
    "m3",
    "network-3",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#webview-server-certificate-verification"
  )

  override def name = "Webview Ignore SSL certificate Error"
}
/*
$RET onReceivedSslError(WebView $W, SslErrorHandler $H, SslError
              $E) {
                ...
                $H.proceed();
              }
*/