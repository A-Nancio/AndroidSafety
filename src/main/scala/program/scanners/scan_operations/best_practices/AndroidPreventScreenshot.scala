package program.scanners.scan_operations

import org.opalj.ai.AIResult
import java.net.URL
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.br.instructions.FieldAccess
import program.HelperFunctions

object AndroidPreventScreenshot extends ScanOperation {
  private var getWindowCall = false
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val operands = interpretation.operandsArray(pc)

    if (methodCall.declaringClass.toJava == "android.view.Window" && methodCall.name == "setFlags" || methodCall.name == "addFlags") {     
      // get the Android window origin
      val windowReference = operands(operands.size - 1)
      val windowOrigin = interpretation.domain.origins(windowReference)
      
      HelperFunctions.findInstruction(windowOrigin.head, interpretation.code) match {
        case inst: MethodInvocationInstruction => 
          if (inst.declaringClass.toJava == "android.app.Activity" && inst.name == "getWindow") {
              
            //check the flag inside the first argument
            val flagReference = operands(0)
            val flagOrigin = interpretation.domain.origins(flagReference)
            HelperFunctions.findInstruction(flagOrigin.head, interpretation.code) match {
              case flag: FieldAccess =>
                return inst.declaringClass.toJava == "android.view.WindowManager.LayoutParams" && inst.name == "FLAG_SECURE"
              
              case _ => return false
            }
          }
        
        case _ => return false
      }
    }
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

/*patterns:
      - pattern-either:
          - pattern: |
              getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, ...);
          - pattern: |
              $V = WindowManager.LayoutParams.FLAG_SECURE;
              ...
              getWindow().setFlags($V);
          - pattern: |
              getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE, ...);
          - pattern: |
              $V = WindowManager.LayoutParams.FLAG_SECURE;
              ...
              getWindow().addFlags($V);
          - pattern: >
              $A.getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
              ...);
          - pattern: |
              $V = WindowManager.LayoutParams.FLAG_SECURE;
              ...
              $A.getWindow().setFlags($V);
          - pattern: >
              $A.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE,
              ...);
          - pattern: |
              $V = WindowManager.LayoutParams.FLAG_SECURE;
              ...
              $A.getWindow().addFlags($V);
*/
