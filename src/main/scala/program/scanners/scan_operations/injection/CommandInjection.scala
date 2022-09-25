package program.scanners.scan_operations.injection

import program.scanners.scan_operations.ScanOperation
import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import program.scanners.scan_operations.SecurityWarning
import org.opalj.br.ObjectType
import org.opalj.br.instructions.LoadString
import program.scanners.scan_operations.CodeTracker

object CommandInjection extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    //NOTE: String array not covered
    val operands = interpretation.operandsArray(pc)
    val runtimeType = ObjectType("java/lang/Runtime")
    if (methodCall.declaringClass == runtimeType && methodCall.name == "exec") {
      return CodeTracker.processMethodCallOrigin(operands.size -1, pc, "java/lang/Runtime", "getRuntime", interpretation) &&
             !CodeTracker.processLoadConstantOrigin(0, pc, interpretation)
    }
    return false
  } 
  
  override def json = SecurityWarning(
    """User controlled strings in exec() will result in command execution.""",
    "ERROR",
    "cwe-78",
    "m7",
    "platform-2",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x04h-Testing-Code-Quality.md#injection-flaws-mstg-arch-2-and-mstg-platform-2"
  )

  override def name = "Command Injection"
}

/*
patterns:
      - pattern-not: 'Runtime.getRuntime().exec("...", ...);'
      - pattern-not: 'Runtime.getRuntime().exec(new String[] {"...", ...}, ...);' -> Cannot check this one
      - pattern-either:
          - pattern: |
              Runtime.getRuntime().exec(...);
*/