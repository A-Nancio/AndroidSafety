package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.br.instructions.FieldAccess
import org.opalj.br.instructions.LoadString

case class SecurityWarning(
  issue: String,
  severity: String,
  standards: Array[String],
  files: Set[String]
)

abstract class  ScanOperation {
  var results = Set[String]() 

  def execute(instruction: MethodInvocationInstruction, callerClass: String): Unit = {
    throw new Exception(s"No ${name} scan provided for method access")
  }
  def execute(instruction: FieldAccess, callerClass: String): Unit = {
    throw new Exception(s"No ${name} scan provided for field access")
  }

  def execute(instruction: LoadString, callerClass: String): Unit = {
    throw new Exception(s"No ${name} scan provided for string constant loading")
  }
  
  def json: SecurityWarning
  def name: String
}