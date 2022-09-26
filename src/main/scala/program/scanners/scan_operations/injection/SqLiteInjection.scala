package program.scanners.scan_operations

import org.opalj.br.instructions.MethodInvocationInstruction
import org.opalj.ai.AIResult
import org.opalj.ai.domain.l1.DefaultDomainWithCFGAndDefUse
import java.net.URL
import org.opalj.br.ObjectType

object SqLiteInjection extends ScanOperation {
  override def execute(methodCall: MethodInvocationInstruction, pc: Int, interpretation: AIResult{val domain: DefaultDomainWithCFGAndDefUse[URL]}): Boolean = {
    val SQLiteDatabaseType = ObjectType("android/database/sqlite/SQLiteDatabase")
    if (methodCall.declaringClass == SQLiteDatabaseType && (methodCall.name == "execSQL" || methodCall.name == "rawQuery")) {
      return !CodeTracker.processLoadConstantOrigin(0, pc, interpretation)
    }
    return false
  }
  
  override def json = SecurityWarning(
    """App uses SQLite Database and execute raw SQL query. Untrusted user input in raw SQL queries can cause SQL Injection. Also sensitive information should be encrypted and written to the database.""",
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