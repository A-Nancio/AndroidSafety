package program.scanners.scan_operations

import org.opalj.ai.AIResult
import java.net.URL
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.br.instructions.FieldAccess
import org.opalj.br.ObjectType

object AndroidPreventScreenshot extends BestPracticeScan {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val operands = interpretation.operandsArray(pc)
    val windowType = ObjectType("android/view/Window")
    if (methodCall.declaringClass == windowType && methodCall.name == "setFlags" || methodCall.name == "addFlags") {     
      // get the Android window origin
      val windowReference = operands(operands.size - 1)
      val windowOrigin = interpretation.domain.origins(windowReference)
      
      if (CodeTracker.processMethodCallOrigin(operands.size - 1, pc , "android/app/Activity", "getWindow", interpretation))
        return CodeTracker.processFieldAccessOrigin(0, pc, "android/view/WindowManager/LayoutParams", "FLAG_SECURE", interpretation)
      
    }
    return false
  }

  override def json = SecurityWarning(
      "This app does not have capabilities to prevent against Screenshots from Recent Task History/ Now On Tap etc.",
      "INFO",
      "cwe-200",
      "m2",
      "storage-9",
      this.results,
      "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#finding-sensitive-information-in-auto-generated-screenshots-mstg-storage-9"
  )

  override def name = "Android screenshot prevention"
}

/*  patterns:
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
