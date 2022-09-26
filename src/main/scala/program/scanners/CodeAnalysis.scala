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
import org.opalj.br.ObjectType
import org.opalj.br.instructions.Instruction
import org.opalj.br.instructions.LoadString

class CodeAnalysis(project: Project[URL]) {


  private val methodScanOperations: Array[ScanOperation] = Array[ScanOperation](
    Logging, HiddenUi, Aes_CbsMode, Aes_CbsModeDefault, Aes_CbsModeDefault,
    CbcPaddingOracle, InsecureRandom, InsecureSslV3, RsaNoOeap, Sha1Hash, WeakChipers,
    JacksonDeserialization, ObjectDeserialization, CommandInjection, SqLiteInjection,
    DefaultHttpClientTls, WebviewDebugging, WebviewFileAccess, WebviewJavascriptInterface,
    XMLDecoder, XMLFactorySupportExternalEntities)
  
  private val bestPracticesOperations: Array[BestPracticeScan] = Array[BestPracticeScan](
    AndroidCertificateTransparency, AndroidDetectTapjacking, AndroidPreventScreenshot, AndroidSafetyNet, RootDetection)

  private val operationsCollection: Array[ScanOperation] = methodScanOperations ++ bestPracticesOperations
  
  private val fieldAccessScanOperations: Array[ScanOperation] = Array[ScanOperation](WorldReadable, WorldWritable)

  def scan(method: Method, classFileName: String): Unit = { 
    
    method.body match {
      case Some(code) => 
        //Obtain CFG and defUses from that 
        val domain = new DefaultDomainWithCFGAndDefUse(project, method)
        lazy val interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]} = PerformAI(domain)
        
        code.foreach(pc_instruction => { pc_instruction.instruction match {          
          case methodCall: MethodInvocationInstruction => {
            operationsCollection.foreach(operation => {
              if (operation.execute(methodCall, pc_instruction.pc, interpretation))
                operation.register(classFileName)
            })
          }
          case fieldAccess: FieldAccess => {
            fieldAccessScanOperations.foreach(operation => {
              if (operation.execute(fieldAccess, pc_instruction.pc))
                operation.register(classFileName)

            })
          }
          case _ => //do nothing
        }})
      case None => //Nothing to scan
      }
  }

  def export: Json = {
    var output: Set[SecurityWarning] = Set[SecurityWarning]()
    
    methodScanOperations foreach 
      (operation => if (!operation.json.files.isEmpty) output += operation.json) 
    
    bestPracticesOperations foreach(operation => {
      if (operation.bestPracticeNotFound) output += operation.json
    })

    fieldAccessScanOperations foreach
      (operation => if (!operation.json.files.isEmpty) output += operation.json)
    return Encoder[Set[SecurityWarning]].apply(output)
  }

  
}