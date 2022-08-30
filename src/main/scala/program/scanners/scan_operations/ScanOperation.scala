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
  
  def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult {val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    throw new Exception(s"No ${name} implementation provided for method call instructions")
  }

  def execute(fieldAccess: FieldAccess, pc: Int): Boolean = {
    throw new Exception(s"No ${name} implementation provided for field access instructions")
  }

  def register(classFile: String): Unit = {
    results += classFile
    //println("Line number: " + lineNumber)
  }
  
  def json: SecurityWarning

  def name: String
}