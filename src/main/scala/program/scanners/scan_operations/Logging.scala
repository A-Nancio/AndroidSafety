package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.br.instructions.Instruction
import org.opalj.br.instructions.FieldAccess
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import org.opalj.ai.domain.l1.StringValues
import simulacrum.op
import java.net.URL
import program.HelperFunctions
import org.opalj.ai.domain.l1.DefaultStringValuesBinding
import org.opalj.br.PCAndInstruction

object Logging extends ScanOperation{
  override def execute(pc_instruction: PCAndInstruction, interpretation: AIResult {val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val instruction = pc_instruction.instruction
   
    if (instruction.isMethodInvocationInstruction) {
      val methodCall = instruction.asMethodInvocationInstruction
      val operands = interpretation.operandsArray(pc_instruction.pc)
      
      //check for Log
      if (methodCall.declaringClass.toJava == "android.util.Log" && 
      Array("d", "e", "i", "v", "w").contains(methodCall.name)) {
        for (index <- 0 until operands.size - 1) {
          val arg = operands(index)
          if (arg.isReferenceValue) {
            return true
          }
        }
        return false
      }
      
      //check for System.out.println && System.out.print
      if (methodCall.declaringClass.toJava == "java.io.PrintStream" && Array("print", "println").contains(methodCall.name)) {
        if (operands.size == 2) { //empty prints log no information
          
          val printStreamReference = operands(operands.size - 1)
          val origin = interpretation.domain.origins(printStreamReference)
          HelperFunctions.findInstruction(origin.head, interpretation.code) match {
            case inst: FieldAccess => 
              return inst.declaringClass.toJava == "java.lang.System" && (inst.name == "out"|| inst.name == "err")
            case _ => return false
          }
        }
      }     
    }
    return false
  } 
  
  override def json = SecurityWarning(
      "The App logs information. Sensitive information should never be logged.",
      "INFO",
      Array("CWE: cwe-532",
            "OWASP-MOBILE : m1",
            "MASVS: storage-3"),
      this.results,
      "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#logs"
    )

  override def name = "Logging usage"
}

/* patterns:
      - pattern-not: System.out.print();
      - pattern-not: System.out.println();
      - pattern-not: System.err.print();
      - pattern-not: System.err.println();
      - pattern-not: 'Log.$D("...", "...", ...);'
      - pattern-not: 'Log.$D($T, "...", ...);'
      - pattern-not: System.out.print("...");
      - pattern-not: System.out.println("...");
      - pattern-not: System.err.print("...");
      - pattern-not: System.err.println("...");
      - pattern-either:
          - pattern: |
              Log.$D($T, $X + "...", ...);
          - pattern: |
              Log.$D($T, "..." + $X + "...", ...);
          - pattern: |
              Log.$D($T, "..." + $X, ...);
          - pattern: |
              $Y = $Z;
              ...
              Log.$D($T,<... $Y ...>, ...);
          - pattern: |
              System.out.print(...);
          - pattern: |
              System.err.print(...);
          - pattern: |
              System.out.println(...);
          - pattern: |
              System.err.println(...);

*/