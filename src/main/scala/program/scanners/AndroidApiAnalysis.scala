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

private case class ApiCategory(name: String, packages: Set[String])

object AndroidApiAnalysis {
  private var results: HashMap[String, Set[String]] 
          = new HashMap[String, Set[String]]()

  private val jsonString = scala.io.Source.fromFile("API_list.json").mkString
  private val api_list = decode[Array[ApiCategory]](jsonString).right.get

  def scan(keyword: String, callerClass: String): Unit = {
    api_list.foreach(category => {
      if (category.packages.contains(keyword))
        results.get(category.name) match {
          case None => results += (category.name -> Set[String]())
          case Some(value) => value += callerClass
        }
    })
  }

  def scan(code: Code, callerClass: String): Unit = {
    val methodCalls = code.collectInstructions{case inst: MethodInvocationInstruction => inst}
    methodCalls.foreach(call => {
      api_list.foreach(category => {
        // list of packages/methods calls contains -> package.methodName 
        if (category.packages.contains(call.declaringClass.toJava + "." + call.name))
        results.get(category.name) match {
          case None => results += (category.name -> Set[String]())
          case Some(value) => value += callerClass
        } 
      })
    })
  }

  def export: Json = {
    val jsonArray = new ArrayBuffer[ApiCategory]()
    for ((category, list) <- results) {
      jsonArray += new ApiCategory(category, list)
    }
    return Encoder[ArrayBuffer[ApiCategory]].apply(jsonArray)
  }
}
