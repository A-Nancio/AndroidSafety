package program.scanners.scan_operations.injection

import program.scanners.scan_operations.ScanOperation
import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import program.scanners.scan_operations.SecurityWarning
import org.opalj.br.ObjectType
import org.opalj.br.instructions.LoadString

object CommandInjection extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val runtimeType = ObjectType("java/lang/Runtime")
    if (methodCall.declaringClass == runtimeType && methodCall.name == "exec") {
      val operands = interpretation.operandsArray(pc)
    
      val commandNameOrigin = interpretation.domain.origins(operands(0))
      val runtimeOrigin = interpretation.domain.origins(operands(operands.size - 1))

      //NOTE: String array not covered
      
      interpretation.code.instructions(runtimeOrigin.head) match {
        case instruction: MethodInvocationInstruction => 
          if (instruction.declaringClass == runtimeType && instruction.name == "getRuntime") {
            interpretation.code.instructions(commandNameOrigin.head) match {
              case stringLoad: LoadString => return false // loading string implies loading always the same command
              case _ => return true  // not constant can generate injections
            }
          }
        case _ => return false
      }
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