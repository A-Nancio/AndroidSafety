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

  def execute(instruction: MethodInvocationInstruction): Boolean = {
    throw new Exception(s"No ${name} implementation provided for method access")
  }
  def execute(instruction: FieldAccess): Boolean = {
    throw new Exception(s"No ${name} implementation provided for field access")
  }

  def execute(instruction: LoadString): Boolean = {
    throw new Exception(s"No ${name} implementation provided for string constant loading")
  }

  def register(classFile: String): Unit = {
    results += classFile
    //println("Line number: " + lineNumber)
  }
  
  def json: SecurityWarning
  def name: String
}