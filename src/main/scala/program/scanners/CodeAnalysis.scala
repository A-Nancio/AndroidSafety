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
    //Obtain CFG and defUses from that 
    val domain = new DefaultDomainWithCFGAndDefUse(project, method)
    lazy val result: AIResult {val domain: DefaultDomainWithCFGAndDefUse[URL]} = PerformAI(domain) 
    
    method.body match {
      case Some(code) => 
        code.foreach(pc_instruction => { pc_instruction.instruction match {          
          
          case access: MethodInvocationInstruction => {
            println("[INSTRUCTION]" + access)
            methodScanOperations.foreach(operation => {
              val res = operation.execute(pc_instruction, result)
              println(res)
              if (res)
                operation.register(classFileName)
            })
          }
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
