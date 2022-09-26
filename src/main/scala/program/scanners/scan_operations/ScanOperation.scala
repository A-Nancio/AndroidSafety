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
import org.opalj.br.analyses.Project
import org.opalj.br.Method
import org.opalj.ai.domain.PerformAI
import org.opalj.value.ValueInformation
import io.circe.CursorOp
import org.opalj.br.ObjectType

case class SecurityWarning(
  message: String,
  severity: String,
  cwe: String,
  owasp_mobile: String,
  masvs: String,
  files: Set[String],
  reference: String
)

abstract class ScanOperation {

  var results = Set[String]() 
  
  def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult {val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    throw new Exception(s"No ${name} implementation provided for method call instructions")
  }

  def execute(fieldAccess: FieldAccess, pc: Int): Boolean = {
    throw new Exception(s"No ${name} implementation provided for field access instructions")
  }

  def register(classFile: String): Unit = {
    results += classFile
  }
  
  def json: SecurityWarning

  def name: String
}

object CodeTracker {
  def processFieldAccessOrigin(argumentIndex: Int, instructionPC: Int, packageName: String, methodName: String,
                              methodInfo: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val operands = methodInfo.operandsArray(instructionPC)
    if (!operands.isEmpty) {
      val reference = operands(argumentIndex)
      val origin = methodInfo.domain.origins(reference)
                                
      if (!origin.isEmpty && origin.head > 0) {
        val instructionOrigin = methodInfo.code.instructions(origin.head)
        instructionOrigin match {
          case fielAccess: FieldAccess => {
            val objType = ObjectType(packageName)
            return fielAccess.declaringClass == objType && fielAccess.name == methodName
          }
          case _ => return false
        }
      }
    }
    return false   
  }

  def processStringLoadOrigin(argumentIndex: Int, instructionPC: Int, keyWords: Array[String],
                              methodInfo: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val operands = methodInfo.operandsArray(instructionPC)
    if (!operands.isEmpty) {
      val reference = operands(argumentIndex)
      val origin = methodInfo.domain.origins(reference)
      if (!origin.isEmpty && origin.head > 0) {
        val instructionOrigin = methodInfo.code.instructions(origin.head)
        instructionOrigin match {
          case stringLoad: LoadString => {
            return keyWords contains stringLoad.value
          }
          case _ => return false
        }
      }
    }
    return false
  }

  def processMethodCallOrigin(argumentIndex: Int, instructionPC: Int, packageName: String, fieldName: String,                            
                              methodInfo: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val operands = methodInfo.operandsArray(instructionPC)
    if (!operands.isEmpty) {
      val reference = operands(argumentIndex)
      val origin = methodInfo.domain.origins(reference)
      
      if (!origin.isEmpty && origin.head > 0) {
        val instructionOrigin = methodInfo.code.instructions(origin.head)
        instructionOrigin match {
          case method: MethodInvocationInstruction => {
            val objType = ObjectType(packageName)
            return method.declaringClass == objType && method.name == fieldName
          }
          case _ => return false
        }
      }
    }
    return false                            
  }

  def processLoadConstantOrigin(argumentIndex: Int, instructionPC: Int,
                              methodInfo: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val operands = methodInfo.operandsArray(instructionPC)
    if (!operands.isEmpty) {
      val reference = operands(argumentIndex)
      val origin = methodInfo.domain.origins(reference)
  
      if (!origin.isEmpty && origin.head > 0) {
        val instructionOrigin = methodInfo.code.instructions(origin.head)
        instructionOrigin match {
          case string: LoadString => return true
          case _ => return false
        }
      }
      return true
    }
    return false
  }
}
