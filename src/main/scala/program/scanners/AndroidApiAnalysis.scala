package program.scanners

import org.opalj.br.analyses.Project
import scala.collection.mutable.ArrayBuffer

import io.circe.Encoder
import io.circe.Json
import io.circe.generic.auto._
import io.circe.parser._
import org.opalj.br.ClassFile
import scala.collection.mutable.HashMap
import play.api.libs.json.JsPath
import org.opalj.br.instructions._

private case class ApiCategory(name: String, packages: ArrayBuffer[String])

object AndroidApiAnalysis {
  private var results: HashMap[String, ArrayBuffer[String]] 
          = new HashMap[String, ArrayBuffer[String]]()

  private val jsonString = scala.io.Source.fromFile("API_list.json").mkString
  private val api_list = decode[Array[ApiCategory]](jsonString).right.get

  def ScanApi(keyword: String, callerClass: String): Unit = {
    api_list.foreach(category => {
      if (category.packages.contains(keyword))
        results.get(category.name) match {
          case None => results += (category.name -> new ArrayBuffer[String]())
          case Some(value) => value += callerClass
        }
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
