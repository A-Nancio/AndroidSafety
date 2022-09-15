package program.scanners.scan_operations.network

import program.scanners.scan_operations.ScanOperation
import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import program.scanners.scan_operations.SecurityWarning
import org.opalj.br.ObjectType

object DefaultHttpClientTls extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val defaultClientType = ObjectType("org/apache/http/impl/client/DefaultHttpClient")
    return methodCall.declaringClass == defaultClientType && 
          methodCall.name == "init" && 
          interpretation.operandsArray(pc).size == 1
  }
  
  override def json = SecurityWarning(
    "DefaultHTTPClient() with default constructor is not compatible with TLS 1.2.",
    "WARNING",
    "cwe-757",
    "m3",
    "network-2",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x04f-Testing-Network-Communication.md#verifying-data-encryption-on-the-network-mstg-network-1-and-mstg-network-2"
  )

  override def name = "Default HTTP Client TLS"
}
/*
atterns:
      - pattern-either:
          - pattern: |
              new DefaultHttpClient()
*/