package program.scanners.scan_operations.injection

import program.scanners.scan_operations.ScanOperation
import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import program.scanners.scan_operations.SecurityWarning
import org.opalj.br.ObjectType
import org.opalj.br.instructions.LoadString

object SqLiteInjection extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val SQLiteDatabaseType = ObjectType("android/database/sqlite/SQLiteDatabase")
    if (methodCall.declaringClass == SQLiteDatabaseType && (methodCall.name == "execSQL" || methodCall.name == "rawQuery")) {
      val operands = interpretation.operandsArray(pc)
      val firstArgumentOrigin = interpretation.domain.origins(operands(0))

      interpretation.code.instructions(firstArgumentOrigin.head) match {
        case stringLoad: LoadString => return false //loading a query from a raw string, it can not be manipulated
        case _ => return true //anything else has a chance to be manipulated by the user
      }
    }
    return false
  }
  
  override def json = SecurityWarning(
    """App uses SQLite Database and execute raw SQL query. Untrusted user input
      in raw SQL queries can cause SQL Injection. Also sensitive information
      should be encrypted and written to the database.""",
    "WARNING",
    "cwe-78",
    "m7",
    "platform-2",
    this.results,
    "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x04h-Testing-Code-Quality.md#injection-flaws-mstg-arch-2-and-mstg-platform-2"
  )

  override def name = "SQL Lite Injection"
}
  
/*
patterns:
      - pattern-not: '$DB.execSQL("..." , ...);'
      - pattern-not: '$DB.rawQuery("..." , ...);'
      - pattern-either:
          - pattern: |
              $DB.rawQuery("..." + $INP + "..." , ...);
          - pattern: |
              $DB.rawQuery($INP + "..." , ... );
          - pattern: |
              $DB.rawQuery($INP + "..." + $INP2, ...);
          - pattern: |
              $DB.rawQuery($INP + "..." + $INP2 + "...", ...);
          - pattern: |
              $DB.execSQL($INP + "..." , ...);
          - pattern: |
              $DB.execSQL("..." + $INP + "..." , ...);
          - pattern: |
              $DB.execSQL($INP + "..." + $INP2, ...);
          - pattern: |
              $DB.execSQL($INP + "..." + $INP2 + "...", ...);
*/