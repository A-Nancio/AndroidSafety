package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.br.instructions.FieldAccess
import org.opalj.br.instructions.LoadString
import org.opalj.issues.Operands
import org.opalj.br.instructions.Instruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import org.opalj.br.Code
import org.opalj.br.PCAndInstruction

case class SecurityWarning(
  message: String,
  severity: String,
  standards: Array[String],
  files: Set[String],
  reference: String
)

abstract class  ScanOperation {
  var results = Set[String]() 
  
  def execute(pc_instruction: PCAndInstruction, interpretation: AIResult {val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    throw new Exception(s"No ${name} implementation provided for method access")
  }
  /*
  def execute(instruction: FieldAccess): Boolean = {
    throw new Exception(s"No ${name} implementation provided for field access")
  }

  def execute(instruction: LoadString): Boolean = {
    throw new Exception(s"No ${name} implementation provided for string constant loading")
  }*/

  def register(classFile: String): Unit = {
    results += classFile
    //println("Line number: " + lineNumber)
  }
  
  def json: SecurityWarning

  def name: String
}