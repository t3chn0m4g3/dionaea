/********************************************************************************
 *                               libemu
 *
 *                    - x86 shellcode emulation -
 *
 *
 * Copyright (C) 2007  Paul Baecher & Markus Koetter
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * 
 * 
 *             contact nepenthesdev@users.sourceforge.net  
 *
 *******************************************************************************/

#include <stdint.h>

/* the signed product at the output width, which holds it in full */
#define INSTR_CALC(inbits, outbits, cpu, a, b) \
INTOF(inbits) operand_a = (INTOF(inbits))a; \
INTOF(inbits) operand_b = (INTOF(inbits))b; \
INTOF(outbits) operation_result = (INTOF(outbits))operand_a * operand_b; \


#include "emu/emu_cpu.h"
#include "emu/emu_cpu_data.h"

#include "emu/emu_memory.h"

/*Intel Architecture Software Developer's Manual Volume 2: Instruction Set Reference (24319102.PDF) page 335*/

/* CF and OF are set when the product does not fit the destination size
 * (inbits): the full product is not the sign extension of its lower half */
#define INSTR_SET_FLAGS(cpu, inbits)	\
if (operation_result == (INTOF(inbits))operation_result) \
{ \
	CPU_FLAG_UNSET(cpu,f_cf); \
	CPU_FLAG_UNSET(cpu,f_of); \
} \
else \
{ \
	CPU_FLAG_SET(cpu,f_cf); \
	CPU_FLAG_SET(cpu,f_of); \
}



int32_t instr_imul_69(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	if ( i->modrm.mod != 3 )
	{
		if ( i->prefixes & PREFIX_OPSIZE )
		{
			/* 69 /r iw 
			 * word register <- r/m16 * immediate word                        
			 * IMUL r16,imm16      
			 *
			 * word register <- r/m16 * immediate word                        
			 * IMUL r16,r/m16,imm16         
			 */
#if BYTE_ORDER == BIG_ENDIAN
			int16_t sexd;
			bcopy(i->imm16, &sexd, 2);
#else
			int16_t sexd = (int16_t)*i->imm16;
#endif
			uint16_t m16;
			MEM_WORD_READ(c, i->modrm.ea, &m16);

			INSTR_CALC(16,
					   32,
					   c, 
					   m16,
					   sexd) 

			*c->reg16[i->modrm.opc] = operation_result;

			INSTR_SET_FLAGS(c,16);

		}
		else
		{
			/* 69 /r id 
			 * doubleword register <- r/m32 * immediate doubleword            
			 * IMUL r32,imm32      
			 *
			 * doubleword register <- r/m32 * immediate doubleword            
			 * IMUL r32,r/m32,imm32         
			 */
			int32_t sexd = (int32_t)i->imm;

			uint32_t m32;
			MEM_DWORD_READ(c, i->modrm.ea, &m32);

			INSTR_CALC(32,
					   64,
					   c, 
					   m32,
					   sexd)

			c->reg[i->modrm.opc] = operation_result;

			INSTR_SET_FLAGS(c,32);
		}
	}
	else
	{
		if ( i->prefixes & PREFIX_OPSIZE )
		{
			/* 69 /r iw 
			 * word register <- r/m16 * immediate word                        
			 * IMUL r16,imm16      
			 *
			 * word register <- r/m16 * immediate word                        
			 * IMUL r16,r/m16,imm16         
			 */
#if BYTE_ORDER == BIG_ENDIAN
			int16_t sexd;
			bcopy(i->imm16, &sexd, 2);
#else
			int16_t sexd = (int16_t)*i->imm16;
#endif


			INSTR_CALC(16,
					   32,
					   c, 
					   *c->reg16[i->modrm.rm],
					   sexd)
			*c->reg16[i->modrm.opc] = operation_result;

			INSTR_SET_FLAGS(c,16);
		}
		else
		{
			/* 69 /r id 
			 * doubleword register <- r/m32 * immediate doubleword            
			 * IMUL r32,imm32      
			 *
			 * doubleword register <- r/m32 * immediate doubleword            
			 * IMUL r32,r/m32,imm32         
			 */ 
			int32_t sexd = (int32_t)i->imm;

			INSTR_CALC(32,
					   64,
					   c, 
					   c->reg[i->modrm.rm],
					   sexd)
			c->reg[i->modrm.opc] = operation_result;

			INSTR_SET_FLAGS(c,32);

		}

	}

	return 0;
}

int32_t instr_imul_6b(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	if ( i->modrm.mod != 3 )
	{
		if ( i->prefixes & PREFIX_OPSIZE )
		{
			/* 6B /r ib 
			 * word register <- m16 * sign-extended immediate byte          
			 * IMUL r16,m16,imm8 
			 */
			int16_t sexd = (int8_t)*i->imm8;

			uint16_t m16;
			MEM_WORD_READ(c, i->modrm.ea, &m16);

			INSTR_CALC(16,
					   32,
					   c, 
					   m16,
					   sexd) 

			*c->reg16[i->modrm.opc] = operation_result;

			INSTR_SET_FLAGS(c,16);
		}
		else
		{
			/* 6B /r ib 
			 * word register <- m16 * sign-extended immediate byte          
			 * IMUL r16,m16,imm8 
			 */

			int32_t sexd = (int8_t)*i->imm8;

			uint32_t m32;
			MEM_DWORD_READ(c, i->modrm.ea, &m32);

			INSTR_CALC(32, 
					   64,
					   c, 
					   m32,
					   sexd)

			c->reg[i->modrm.opc] = operation_result;

			INSTR_SET_FLAGS(c,32);
		}
	}
	else
	{
		if ( i->prefixes & PREFIX_OPSIZE )
		{
			/* 6B /r ib 
			 * word register <- r16 * sign-extended immediate byte          
			 * IMUL r16,r16,imm8 
			 *
			 * word register <- word register * sign-extended immediate byte                                                                
			 * IMUL r16,imm8       
			 */
			int16_t sexd = (int8_t)*i->imm8;

			INSTR_CALC(16,
					   32,
					   c, 
					   *c->reg16[i->modrm.rm],
					   sexd)
			*c->reg16[i->modrm.opc] = operation_result;

			INSTR_SET_FLAGS(c,16);
		}
		else
		{
			/* 6B /r ib 
			 * doubleword register <- r32 * sign-extended immediate byte                                                                
			 * IMUL r32,r32,imm8 
			 *
			 * doubleword register <- doubleword register * sign-extended immediate byte                                             
			 * IMUL r32,imm8       
			 */
			int32_t sexd = (int8_t)*i->imm8;

			INSTR_CALC(32,
					   64,
					   c, 
					   c->reg[i->modrm.rm],
					   sexd)
			c->reg[i->modrm.opc] = operation_result;

			INSTR_SET_FLAGS(c,32);
		}
	}
	return 0;
}


int32_t instr_imul_0f_af(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	if ( i->modrm.mod != 3 )
	{
		if ( i->prefixes & PREFIX_OPSIZE )
		{
			/* 0F AF /r 
			 * word register <- word register * r/m word                      
			 * IMUL r16,r/m16      
			 */                                                                                              
			uint16_t m16;
			MEM_WORD_READ(c, i->modrm.ea, &m16);

			INSTR_CALC(16,
					   32,
					   c, 
					   *c->reg16[i->modrm.opc],
					   m16)

			*c->reg16[i->modrm.opc] = operation_result;

			INSTR_SET_FLAGS(c,16);
		}
		else
		{
			/* 0F AF /r 
			 * doubleword register <- doubleword register * r/m doubleword                                                          
			 * IMUL r32,r/m32      
			 */
			uint32_t m32;
			MEM_DWORD_READ(c, i->modrm.ea, &m32);

			INSTR_CALC(32,
					   64,
					   c, 
					   c->reg[i->modrm.opc],
					   m32)

			c->reg[i->modrm.opc] = operation_result;

			INSTR_SET_FLAGS(c,32);
		}
	}
	else
	{
		if ( i->prefixes & PREFIX_OPSIZE )
		{
			/* 0F AF /r 
			 * word register <- word register * r/m word                      
			 * IMUL r16,r/m16      
			 */                                                                                              
			INSTR_CALC(16,
					   32,
					   c, 
					   *c->reg16[i->modrm.opc],
					   *c->reg16[i->modrm.rm])

			*c->reg16[i->modrm.opc] = operation_result;

			INSTR_SET_FLAGS(c,16);
		}
		else
		{
			/* 0F AF /r 
			 * doubleword register <- doubleword register * r/m doubleword                                                          
			 * IMUL r32,r/m32      
			 */
			INSTR_CALC(32,
					   64,
					   c, 
					   c->reg[i->modrm.opc],
					   c->reg[i->modrm.rm])

			c->reg[i->modrm.opc] = operation_result;

			INSTR_SET_FLAGS(c,32);
		}
	}
	return 0;
}



int32_t instr_group_3_f6_imul(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	if ( i->modrm.mod != 3 )
	{
		/* F6 /5    
		 * AX<- AL * r/m byte                                             
		 * IMUL r/m8			 
		 */

		uint8_t m8;
		MEM_BYTE_READ(c, i->modrm.ea, &m8);
		INSTR_CALC(8, 
				   16,
				   c,
				   *c->reg8[al],
				   m8)
		*c->reg16[ax] = operation_result;
		INSTR_SET_FLAGS(c,8);
	}
	else
	{
		/* F6 /5    
		 * AX<- AL * r/m byte                                             
		 * IMUL r/m8			 
		 */
		INSTR_CALC(8,
				   16,
				   c,
				   *c->reg8[al],
				   *c->reg8[i->modrm.rm])

		*c->reg16[ax] = operation_result;
		INSTR_SET_FLAGS(c,8);
	}
	return 0;
}

int32_t instr_group_3_f7_imul(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	if ( i->modrm.mod != 3 )
	{
		if ( i->prefixes & PREFIX_OPSIZE )
		{
			/* F7 /5    
			 * DX:AX <- AX * r/m word                                         
			 * IMUL r/m16          
			 */
			uint16_t m16;
			MEM_WORD_READ(c, i->modrm.ea, &m16);
			INSTR_CALC(16,
					   32,
					   c,
					   *c->reg16[al],
					   m16)

			DWORD_UPPER_TO_WORD(*c->reg16[dx],operation_result);
			DWORD_LOWER_TO_WORD(*c->reg16[ax],operation_result);

			INSTR_SET_FLAGS(c,16);
		}
		else
		{
			/* F7 /5    
			 * EDX:EAX <- EAX * r/m doubleword                                
			 * IMUL r/m32          
			 */      
			uint32_t m32;
			MEM_DWORD_READ(c, i->modrm.ea, &m32);
			INSTR_CALC(32,
					   64,
					   c,
					   c->reg[eax],
					   m32)

			QWORD_UPPER_TO_DWORD(c->reg[edx],operation_result);
			QWORD_LOWER_TO_DWORD(c->reg[eax],operation_result);

			INSTR_SET_FLAGS(c,32);

		}
	}
	else
	{
		if ( i->prefixes & PREFIX_OPSIZE )
		{
			/* F7 /5    
			 * DX:AX <- AX * r/m word                                         
			 * IMUL r/m16          
			 */
			INSTR_CALC(16,
					   32,
					   c,
					   *c->reg16[al],
					   *c->reg16[i->modrm.rm])
			DWORD_UPPER_TO_WORD(*c->reg16[dx],operation_result);
			DWORD_LOWER_TO_WORD(*c->reg16[ax],operation_result);

			INSTR_SET_FLAGS(c,16);

		}
		else
		{
			/* F7 /5    
			 * EDX:EAX <- EAX * r/m doubleword                                
			 * IMUL r/m32          
			 */                                                                                              
			INSTR_CALC(32,
					   64,
					   c,
					   c->reg[eax],
					   c->reg[i->modrm.rm])

			QWORD_UPPER_TO_DWORD(c->reg[edx],operation_result);
			QWORD_LOWER_TO_DWORD(c->reg[eax],operation_result);

			INSTR_SET_FLAGS(c,32);
		}
	}
	return 0;
}

