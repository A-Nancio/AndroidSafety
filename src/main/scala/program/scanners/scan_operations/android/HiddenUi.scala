package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.br.instructions.FieldAccess
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import org.opalj.ai.AIResult
import java.net.URL
import org.opalj.br.ObjectType

object HiddenUi extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val operands = interpretation.operandsArray(pc)
    val viewType = ObjectType("android/view/View")
    //AbstractInterpretation.verifyStringLoadOrigin(interpretation, pc, 0)
    if (methodCall.declaringClass == viewType)
      return CodeTracker.processFieldAccessOrigin(0, pc, "android/view/View", "INVISIBLE", interpretation) ||
             CodeTracker.processFieldAccessOrigin(0, pc, "android/view/View", "GONE", interpretation)

    return false
  }

  override def json = SecurityWarning(
    "Hidden elements in view can be used to hide data from user. But this data can be leaked.",
    "ERROR",
    "cwe-919",
    "m1",
    "storage-7",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#checking-for-sensitive-data-disclosure-through-the-user-interface-mstg-storage-7"
  ) 

  override def name = "HiddenUI"
}
/*
patterns:
      - pattern-either:
          - pattern: |
              $X.setVisibility(View.GONE);
          - pattern: |
              $V = View.GONE;
              ...
              $X.setVisibility($V);
          - pattern: |
              $X.setVisibility(View.INVISIBLE);
          - pattern: |
              $V = View.INVISIBLE;
              ...
              $X.setVisibility($V);
*/