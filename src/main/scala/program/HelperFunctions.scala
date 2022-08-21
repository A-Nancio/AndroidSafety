package program

import org.opalj.br.Code
import org.opalj.br.instructions.Instruction

object HelperFunctions {
  def findInstruction(pc: Int, code: Code): Instruction = {
    code.iterate { (program_counter: Int, instruction: Instruction) =>
      if (program_counter == pc) return instruction
    }
    return null
  }
}
