package program.scanners

import scala.collection.mutable.Set
import scala.collection.mutable.ArrayBuffer
import scala.collection.mutable.HashMap

import io.circe.Encoder
import io.circe.Json
import io.circe.generic.auto._
import io.circe.parser._

import org.opalj.br.instructions._
import org.opalj.br.analyses.Project
import org.opalj.br.ClassFile
import org.opalj.br.Code

import play.api.libs.json.JsPath
import org.opalj.br.Method
import scala.annotation.meta.field
import org.opalj.br.Field

private case class ApiCategory(name: String, keywords: Set[String], methods: Set[String])
private case class ApiListing(name: String, classFiles: Set[String])

object AndroidApiAnalysis {
  private var results: HashMap[String, Set[String]] = new HashMap[String, Set[String]]()
  private var currentProcessingClassFile = ""
  private val jsonString = scala.io.Source.fromFile("API_list.json").mkString
  private val api_list = decode[Array[ApiCategory]](jsonString).right.get

  def scan(field: Field, callerClass: String): Unit = {
    currentProcessingClassFile = callerClass
    matchFromKeyword(field.fieldType.toJava)
  }

  def scan(method: Method, callerClass: String): Unit = {
    currentProcessingClassFile = callerClass
     method.body match {
      case Some(code) => {
        code.instructions foreach (instruction => {
          instruction match {
            case methodCall: MethodInvocationInstruction => matchFromMethod(methodCall.declaringClass.toJava + "." + methodCall.name)
            case fieldAccess: FieldAccess => matchFromKeyword(fieldAccess.declaringClass.toJava + "." + fieldAccess.name)
            case _ => //check nothing
          }
        })
      }
      case None => //nothing to scan
    }
  }

  private def matchFromKeyword(string: String): Unit = {
    api_list foreach(category =>{
      category.keywords foreach(keyword => {
        if (keyword contains string)
          results.get(category.name) match {
              case None => results += (category.name -> Set[String]())
              case Some(value) => value += currentProcessingClassFile
          } 
      })
    })
  }

  private def matchFromMethod(string: String): Unit = {
    api_list foreach(category =>{
      category.methods foreach(method => {
        if (method contains string)
          results.get(category.name) match {
              case None => results += (category.name -> Set[String]())
              case Some(value) => value += currentProcessingClassFile
          } 
      })
    })
  }

  def export: Json = {
    val jsonArray = new ArrayBuffer[ApiListing]()
    for ((category, list) <- results) {
      jsonArray += new ApiListing(category, list)
    }
    return Encoder[ArrayBuffer[ApiListing]].apply(jsonArray)
  }
}
