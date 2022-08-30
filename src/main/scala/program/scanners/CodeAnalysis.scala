package program.scanners

import io.circe.Json
import io.circe.Encoder
import io.circe.generic.auto._
import io.circe.parser._

import scala.collection.mutable.Set
import program.scanners.scan_operations._

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.br.PCAndInstruction
import org.opalj.br.Code
import org.opalj.br.analyses.Project
import java.net.URL
import org.opalj.br.Method
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import org.opalj.ai.AIResult
import org.opalj.ai.domain.PerformAI
import org.opalj.tac.fpcf.analyses.purity.LoggingRater
import org.opalj.br.instructions.FieldAccess

class CodeAnalysis(project: Project[URL]) {
  private val methodScanOperations: Array[ScanOperation] = Array[ScanOperation](
    Logging)
    /*Base64,*/
    /*ClipboardUsage,
    RawQuery,
    ReadWriteStorage,
    TempFile,
    WeakNumberGenerator
  */
  private val scanOperations = methodScanOperations

  def scan(method: Method, classFileName: String): Unit = { 
    
    method.body match {
      case Some(code) => 
        //Obtain CFG and defUses from that 
        val domain = new DefaultDomainWithCFGAndDefUse(project, method)
        lazy val result: AIResult {val domain: DefaultDomainWithCFGAndDefUse[URL]} = PerformAI(domain) 
        
        code.foreach(pc_instruction => { pc_instruction.instruction match {          
          case methodCall: MethodInvocationInstruction => {
            println("[INSTRUCTION]: " + pc_instruction.instruction)
            methodScanOperations.foreach(operation => {
              val res = operation.execute(methodCall, pc_instruction.pc, result)
              println(res)
              if (res)
                operation.register(classFileName)
            })
          }
          case fieldAccess: FieldAccess => {}
          case _ => //no matches found
        }})
      case None => //Nothing to scan
      }
  }

  def export(): Json = {
    val output = scanOperations.map(operation => operation.json)
    return Encoder[Array[SecurityWarning]].apply(output)
  }
}
