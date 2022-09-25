package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.br.instructions.Instruction
import org.opalj.br.instructions.FieldAccess
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import org.opalj.ai.AIResult
import java.net.URL
import org.opalj.br.instructions.LoadString
import org.opalj.br.ObjectType
import cats.instances.string
import org.opalj.ai.domain.l0.TypeLevelIntegerValues
import org.opalj.value.IsIntegerValue

object Logging extends ScanOperation{
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult {val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
   
    val operands = interpretation.operandsArray(pc)
    
    //check for Log
    if (methodCall.declaringClass == ObjectType("android/util/Log") && 
    Array("d", "e", "i", "v", "w").contains(methodCall.name)) {
      for (index <- 0 until operands.size - 1) {
        return !CodeTracker.processLoadConstantOrigin(index, pc, interpretation)
      }
      return false
    }
    
    //check for System.out.println && System.out.print
    if (methodCall.declaringClass == ObjectType("java/io/PrintStream") && Array("print", "println").contains(methodCall.name)) {
      if (operands.size == 2) { //empty prints log no information
        
        //get origins of both arguments
        return !CodeTracker.processLoadConstantOrigin(0, pc, interpretation) && 
                (CodeTracker.processFieldAccessOrigin(1, pc, "java/lang/System", "out", interpretation) ||
                CodeTracker.processFieldAccessOrigin(1, pc, "java/lang/System", "err", interpretation))
      }
    }     
    return false
  } 
  
  override def json = SecurityWarning(
      "The App logs information. Sensitive information should never be logged.",
      "INFO",
      "cwe-532",
      "m1",
      "storage-3",
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