package program.scanners

import io.circe.Json
import io.circe.Encoder
import io.circe.generic.auto._
import io.circe.parser._
import scala.collection.mutable.Set
import AndroidApiAnalysis.ScanApi
import program.scanners.scan_operations._


object CodeAnalysis {
  val methodScanOperations: Array[ScanOperation] = Array[ScanOperation](
    /*Base64,*/
    Log,
    WeakNumberGenerator,
    ReadWriteStorage,
    RawQuery
  )

  def export(): Json = {
    val output = methodScanOperations.map(operation => operation.json)
    return Encoder[Array[SecurityWarning]].apply(output)
  }
}
