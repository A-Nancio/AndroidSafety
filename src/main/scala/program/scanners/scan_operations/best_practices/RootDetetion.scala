package program.scanners.scan_operations

import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import org.opalj.br.instructions.MethodInvocationInstruction

object RootDetetion extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    return methodCall.name == "isJailBroken" ||
          methodCall.name == "isDeviceRooted" ||
          methodCall.name == "isRooted" ||
          (methodCall.declaringClass.toJava == "com.stericson.RootTools.RootTools.isAccessGiven" &&
          methodCall.name == "isAccessGiven")   
  }
  
  override def json = SecurityWarning(
      "This app does not have root detection capabilities. Running a sensitive application on a rooted device questions the device integrity and affects users data.",
      "INFO",
      Array("CWE: cwe-919",
            "OWASP-MOBILE: m8",
            "MASVS: resilience-1"),
      this.results,
      "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md#testing-root-detection-mstg-resilience-1"
  )

  override def name = "Root Detection"
}

/* patterns:
      - pattern-either:
          - pattern: |
              $J.isJailBroken(...)
          - pattern: |
              $R.isDeviceRooted(...)
          - pattern: |
              $R.isRooted(...)
          - pattern: |
              RootTools.isAccessGiven(...)
          - pattern: |
              $MTD.contains("test-keys") // NOTE MISSING  
*/