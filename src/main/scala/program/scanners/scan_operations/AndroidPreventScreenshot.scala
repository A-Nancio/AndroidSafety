package program.scanners.scan_operations

import org.opalj.ai.AIResult
import org.opalj.br.PCAndInstruction
import java.net.URL
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse

object AndroidPreventScreenshot extends ScanOperation {

  override def execute(pc_instruction: PCAndInstruction, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    return false  
  }

  override def json = SecurityWarning(
      "This app does not have capabilities to prevent against Screenshots from Recent Task History/ Now On Tap etc.",
      "INFO",
      Array(
        "CWE: cwe-200",
        "OWASP-MOBILE: m2",
        "MASVS: storage-9"),
      this.results,
      "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#finding-sensitive-information-in-auto-generated-screenshots-mstg-storage-9"
  )

  override def name = "Android screenshot prevention"

  
  
}
