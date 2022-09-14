package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.br.instructions.Instruction
import org.opalj.br.instructions.FieldAccess
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import org.opalj.ai.AIResult
import java.net.URL
import program.HelperFunctions
import org.opalj.br.instructions.LoadString
import org.opalj.br.ObjectType
import cats.instances.string

object Logging extends ScanOperation{
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult {val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
   
    val operands = interpretation.operandsArray(pc)
    
    //check for Log
    if (methodCall.declaringClass.toJava == "android.util.Log" && 
    Array("d", "e", "i", "v", "w").contains(methodCall.name)) {
      for (index <- 0 until operands.size - 1) {
        val arg = operands(index)
        if (arg.isReferenceValue) { //NOTE: might be wrong
          return true
        }
      }
      return false
    }
    
    //check for System.out.println && System.out.print
    val aux = ObjectType("java/io/PrintStream")
    if (methodCall.declaringClass == aux && Array("print", "println").contains(methodCall.name)) {
      if (operands.size == 2) { //empty prints log no information
        //get origins of both arguments
        val stringOrigin = interpretation.domain.origins(operands(0))
        val printStreamOrigin = interpretation.domain.origins(operands(operands.size - 1))
        //get the corresponding instructions
        
        if (!stringOrigin.isEmpty) {
          val stringLoad = interpretation.code.instructions(stringOrigin.head)
          val printStreamAccess = interpretation.code.instructions(printStreamOrigin.head)
          (stringLoad, printStreamAccess) match {
            case (stringLoad: LoadString, printStreamAccess: FieldAccess) => 
              return printStreamAccess.declaringClass.toJava == "java.lang.System" && (printStreamAccess.name == "out"|| printStreamAccess.name == "err")
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