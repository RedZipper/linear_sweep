package disassembler;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Stack;

/*
  
  @author Christina Ford
  @date 2/22/2015

 This file is part of the Simple Intel 32-bit Dissasembler (SI 32D).

 SI 32D is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 SI 32D is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 You should have received a copy of the GNU General Public License along with SI 32D.  
 If not, see <http://www.gnu.org/licenses/>.

*/

public class LinearSweep {

    // constructor; takes in the file name.
    public LinearSweep(String filename) {
        this.filename = filename;
        initMap();

    }

    private String immval =""; //used for  hexidecimal representation of numbers w/Format String.
    private int count; //keep track of bytes in the file.
    private String modBit, regBit, rmBit; //split MOD R/M byte into a string of 8 bits.
    private boolean addAndFriends = false; //shortcut for add/and/cmp/or/test/xor

    //keep track of jmp and calls
    private int jmp_addr;
    private final Stack<String> offsets = new Stack<>(); //used for holding offsets of subroutines

    private int opcode; //the byte read by the disassembler
    private String bigEndianBytes = ""; //used to display bytes alongside the intructions
    private String instrVal = ""; //instruction
    private final String filename; //binary exe name
    private final HashMap<Integer, String> opcodeMap = new HashMap <>(); //used for opcode lookup table
    private BufferedInputStream buff; // to read in file

    //Function to retrieve instructions that do not have a modr/m byte.
    private int getDispForNonMod() {

        int disp = 0x00;
        int b1, b2;
        immval = "0x";
        bigEndianBytes = "";

        //Did we find any of these: add/and/cmp/or/test/xor ?
        if (addAndFriends) {

            b1 = get32BitNum();

            bigEndianBytes = String.format("%08x", b1);

            disp = 5;
            addAndFriends = false;

            immval += String.format("%08x", reverseByteOrder32(b1));

        } else if (opcode == 0xcd) { //int imm8

            b1 = getByte();

            bigEndianBytes = String.format("%02x", b1);

            immval += String.format("%02x", b1);

            disp = 2;
        } else if ((0xb7 < opcode) && (0xC0 > opcode)) { //mov : imm32
            //get register val

            b1 = get32BitNum();
            bigEndianBytes = String.format("%08x", b1);

            immval += String.format("%08x", reverseByteOrder32(b1));

            disp = 5;

        } else if (0xc2 == opcode) { //  ret imm16

            b2 = getByte();
            b2 <<= 8;
            b1 = getByte();
            b2 += b1;

            bigEndianBytes = String.format("%04x", b2);

            immval += String.format("%04x", reverseByteOrder16(b2));

            disp = 3;

        } else if (0x6A == opcode) { //push imm8

            b1 = getByte();

            bigEndianBytes = String.format("%02x", b1);

            immval += String.format("%02x", b1);
            disp = 2;

        } else if (0x68 == opcode) { //push imm32

            b1 = get32BitNum();
            bigEndianBytes = String.format("%08x", b1);
            b1 = reverseByteOrder32(b1);

            immval += String.format("%08x", b1);
            disp = 5;

        } else if (opcode == 0xe8) { // call rel32

            b1 = get32BitNum();

            disp = 5;

            bigEndianBytes = String.format("%08x", b1);
            b1 = reverseByteOrder32(b1);
            b1 = getOffset32(b1, disp);

            immval = "loc_0x" + String.format("%08x", b1);
            offsets.add(immval);

        } else if (opcode == 0xe9) { //jmp rel32
            b1 = get32BitNum();

            disp = 5;

            bigEndianBytes = String.format("%08x", b1);
            b1 = reverseByteOrder32(b1);
            b1 = getOffset32(b1, disp);

            immval = "offset_0x" + String.format("%08x", b1);
            offsets.add(immval);

        } else if (opcode == 0xeb) { //jmp rel8

            b1 = getByte();

            disp = 2;

            bigEndianBytes = String.format("%02x", b1);
            b1 = getOffset(b1, disp);

            immval = "offset_0x" + String.format("%02x", b1);
            offsets.add(immval);

        } else if (opcode == 0x74) { //jz rel8

            //get offset 
            b1 = getByte();

            disp = 2;

            bigEndianBytes = String.format("%02x", b1);
            b1 = getOffset(b1, disp);

            immval = "offset_0x" + String.format("%02x", b1);
            offsets.add(immval);
        } else if (opcode == 0x75) { //jnz rel8

            b1 = getByte();

            disp = 2;

            bigEndianBytes = String.format("%02x", b1);
            b1 = getOffset(b1, disp);
            immval = "offset_0x" + String.format("%02x", b1);
            offsets.add(immval);
        } else if (opcode == 0x0f84) { //jz rel32

            b1 = get32BitNum();

            disp = 6;

            bigEndianBytes = String.format("%08x", b1);

            b1 = reverseByteOrder32(b1);
            b1 = getOffset32(b1, disp);

            immval = "offset_0x" + String.format("%08x", b1);
            offsets.add(immval);

        } else if (opcode == 0x0f85) { //jnz rel32

            b1 = get32BitNum();

            disp = 6;

            bigEndianBytes = String.format("%08x", b1);

            b1 = reverseByteOrder32(b1);
            b1 = getOffset32(b1, disp);

            immval = "offset_0x" + String.format("%08x", b1);
            offsets.add(immval);
        }

        return disp;
    }

    //Build a mapping of opcodes to instructions.
    private void initMap() {

        //the following opcodes do not require a MODR/M byte
        opcodeMap.put(0x05, "add eax,"); //add eax, imm32
        opcodeMap.put(0x25, "and eax,"); //and eax, imm32
        opcodeMap.put(0x3d, "cmp eax,"); //cmp eax, imm32
        opcodeMap.put(0x35, "xor eax,"); //xor eax, imm32
        opcodeMap.put(0xA9, "test eax,"); //test eax, imm32
        opcodeMap.put(0x0d, "or eax,");//or eax,imm32

        opcodeMap.put(0x40, "inc eax");
        opcodeMap.put(0x41, "inc ecx");
        opcodeMap.put(0x42, "inc edx");
        opcodeMap.put(0x43, "inc ebx");
        opcodeMap.put(0x44, "inc esp");
        opcodeMap.put(0x45, "inc ebp");
        opcodeMap.put(0x46, "inc esi");
        opcodeMap.put(0x47, "inc edi");

        opcodeMap.put(0x48, "dec eax");
        opcodeMap.put(0x49, "dec ecx");
        opcodeMap.put(0x4A, "dec edx");
        opcodeMap.put(0x4B, "dec ebx");
        opcodeMap.put(0x4C, "dec esp");
        opcodeMap.put(0x4D, "dec ebp");
        opcodeMap.put(0x4E, "dec esi");
        opcodeMap.put(0x4F, "dec edi");

        opcodeMap.put(0x50, "push eax");
        opcodeMap.put(0x51, "push ecx");
        opcodeMap.put(0x52, "push edx");
        opcodeMap.put(0x53, "push ebx");
        opcodeMap.put(0x54, "push esp");
        opcodeMap.put(0x55, "push ebp");
        opcodeMap.put(0x56, "push esi");
        opcodeMap.put(0x57, "push edi");

        opcodeMap.put(0x58, "pop eax");
        opcodeMap.put(0x59, "pop ecx");
        opcodeMap.put(0x5A, "pop edx");
        opcodeMap.put(0x5B, "pop ebx");
        opcodeMap.put(0x5C, "pop esp");
        opcodeMap.put(0x5D, "pop ebp");
        opcodeMap.put(0x5E, "pop esi");
        opcodeMap.put(0x5F, "pop edi");

        opcodeMap.put(0xcc, "int 3");
        opcodeMap.put(0xc3, "ret");
        opcodeMap.put(0x90, "nop");

        opcodeMap.put(0xcd, "int:imm8"); //int imm8

        //branches
        opcodeMap.put(0xeb, "jmp:rel8");
        opcodeMap.put(0xe8, "call:rel32");
        opcodeMap.put(0xe9, "jmp:rel32");
        opcodeMap.put(0x0f84, "jz:rel32"); // JZ rel32
        opcodeMap.put(0x74, "jz:rel8"); //JZ rel8
        opcodeMap.put(0x0f85, "jnz:rel32"); //jnz rel32
        opcodeMap.put(0x75, "jnz:rel8"); //jnz rel8

        opcodeMap.put(0xb8, "mov eax,:imm32"); //mov r32, imm32
        opcodeMap.put(0xb9, "mov ecx,:imm32");
        opcodeMap.put(0xba, "mov edx,:imm32");
        opcodeMap.put(0xbb, "mov ebx,:imm32");
        opcodeMap.put(0xbc, "mov esp,:imm32");
        opcodeMap.put(0xbd, "mov ebp,:imm32");
        opcodeMap.put(0xbe, "mov esi,:imm32");
        opcodeMap.put(0xbf, "mov edi,:imm32");

        opcodeMap.put(0x6A, "push:imm8"); //push imm8
        opcodeMap.put(0x68, "push:imm32"); //push imm32
        opcodeMap.put(0xc2, "ret:imm16"); //ret imm16

        //--------------------//
        //the following opcodes require a MODR/M byte
        opcodeMap.put(0x81, "mod"); //could be: add,and,cmp,or, xor
        opcodeMap.put(0x83, "mod"); //same as above
        opcodeMap.put(0xff, "mod"); //could be: call, dec, inc, jmp, push  
        opcodeMap.put(0xd1, "mod"); //could be sal,sar,shl,shr [rm/32, 1]
        opcodeMap.put(0xc1, "mod"); //could be sal,rar,shl,shr [rm/32, imm8]

        opcodeMap.put(0x01, "mod"); //add r/m32,r32
        opcodeMap.put(0x03, "mod"); //add r32,rm32
        opcodeMap.put(0x21, "mod");
        opcodeMap.put(0x23, "mod");
        opcodeMap.put(0x39, "mod");
        opcodeMap.put(0x3b, "mod");
        opcodeMap.put(0x8d, "mod"); //lea r32,m
        opcodeMap.put(0x89, "mod");
        opcodeMap.put(0x8b, "mod"); //mov r32,r/m32
        opcodeMap.put(0xc7, "mod"); //mov r/m32, imm32

        opcodeMap.put(0x0f1f, "mod"); //
        opcodeMap.put(0x09, "mod"); //
        opcodeMap.put(0x0b, "mod"); //
        opcodeMap.put(0x8f, "mod"); //
        opcodeMap.put(0xf30fb8, "mod"); //popcnt r32,r/m32

        opcodeMap.put(0xf7, "mod");// test r/m32, imm32
        opcodeMap.put(0x85, "mod"); //test r/m32, r32
        opcodeMap.put(0x31, "mod"); //xor r/m32,r32
        opcodeMap.put(0x32, "mod"); //xor r32,r32

    }

    //Builds a String based version of the MODR/M Byte.
    //For ease of bit retrieval.
    private void setModRMByte(int val) {

        String mod_rm_byte = Integer.toBinaryString(val);

        int len = mod_rm_byte.length();

        //make sure we pad our mod_rm_byte string if it's less
        //than 8 characters long. 
        if (len == 7) {

            String old_mod = mod_rm_byte;
            mod_rm_byte = "0".concat(old_mod);

        } else if (len == 6) {

            String old_mod = mod_rm_byte;
            mod_rm_byte = "00".concat(old_mod);

        } else if (len == 5) {

            String old_mod = mod_rm_byte;
            mod_rm_byte = "000".concat(old_mod);

        } else if (len == 4) {

            String old_mod = mod_rm_byte;
            mod_rm_byte = "0000".concat(old_mod);

        } else if (len == 3) {

            String old_mod = mod_rm_byte;
            mod_rm_byte = "00000".concat(old_mod);

        } else if (len == 2) {

            String old_mod = mod_rm_byte;
            mod_rm_byte = "000000".concat(old_mod);

        } else if (len == 1) {

            String old_mod = mod_rm_byte;
            mod_rm_byte = "0000000".concat(old_mod);

        }
        //Get the top two bits for the mod bits
        modBit = mod_rm_byte.substring(0, 2);

        //Get the Reg Bit 
        regBit = mod_rm_byte.substring(2, 5);

        //Get the R/M bits from from the MODR/M Byte
        rmBit = mod_rm_byte.substring(5, 8);

    }

    /*
     * Calculates displacement out MOD REG/RM Byte 
     * Also labels instructions with the MOD R/M Byte.
     */
    private int getDispForModRMByte(int val) {

        String reg = "";
        String rm32 = "";
        int b1;
        String ins;
        immval = "0x";
        instrVal = "";
        int disp = 0;

        bigEndianBytes = "";

        setModRMByte(val);

        //determine what mode we're operating in:
        // 00: [reg], 
        // 01: [reg + byte], 
        // 10: [reg + dword], 
        // 11: reg
        switch (modBit) {
            case "00":
                switch (rmBit) {
                    case "000": //0
                        rm32 = "[eax]";
                        break;
                    case "001": //1
                        rm32 = "[ecx]";
                        break;
                    case "010": //2
                        rm32 = "[edx]";
                        break;
                    case "011": //3
                        rm32 = "[ebx]";
                        break;
                    case "100":
                        instrVal = "Unsupported Encoding: SIB Byte Present.";
                        disp = 2;
                        return disp;
                    //Unsupported opcode: SIB Byte Present;
                    case "101": //5
                        b1 = get32BitNum();
                        bigEndianBytes = String.format("%08x", b1);

                        rm32 = "[0x" + String.format("%08x", reverseByteOrder32(b1)) + "]";
                        break;
                    case "110": //6
                        rm32 = "[esi]";
                        break;
                    case "111": //7
                        rm32 = "[edi]";
                        break;
                }
                break;

            case "01":
                b1 = getByte();
                bigEndianBytes = String.format("%02x", b1);

                disp++;
                immval += String.format("%02x", b1);

                switch (rmBit) {
                    case "000": //2
                        rm32 = "[eax+" + immval + "]";
                        break;
                    case "001": //1
                        rm32 = "[ecx+" + immval + "]";
                        break;
                    case "010": //2
                        rm32 = "[edx+" + immval + "]";
                        break;
                    case "011": //3
                        rm32 = "[ebx+" + immval + "]";
                        break;
                    case "100": //4
                        instrVal = "Unsupported Opcode: SIB Byte Present.";
                        disp += 2;
                        return disp;
                    case "101": //5
                        rm32 = "[ebp+" + immval + "]";
                        break;
                    case "110": //6
                        rm32 = "[esi+" + immval + "]";
                        break;
                    case "111": //7
                        rm32 = "[edi+" + immval + "]";
                        break;
                }

                break;

            case "10":

                b1 = get32BitNum();
                bigEndianBytes = String.format("%08x", b1);

                immval += String.format("%08x", reverseByteOrder32(b1));
                disp += 5;

                switch (rmBit) {
                    case "000": //0
                        rm32 = "[eax+" + immval + "]";
                        break;
                    case "001": //1
                        rm32 = "[ecx+" + immval + "]";
                        break;
                    case "010": //2
                        rm32 = "[edx+" + immval + "]";
                        break;
                    case "011": //3
                        rm32 = "[ebx+" + immval + "]";
                        break;
                    case "100": //4
                        instrVal = "Unsupported Opcode: SIB Byte Present.";
                        disp += 2;
                        return disp;
                    case "101": //5
                        rm32 = "[ebp+" + immval + "]";
                        break;
                    case "110": //6
                        rm32 = "[esi+" + immval + "]";
                        break;
                    case "111": //7
                        rm32 = "[edi+" + immval + "]";
                        break;
                    default:
                        rm32 = "[" + immval + "]";
                        break;
                }
                break;

            case "11":
                switch (rmBit) {
                    case "000": //0
                        rm32 = "eax";
                        break;
                    case "001": //1
                        rm32 = "ecx";
                        break;
                    case "010": //2
                        rm32 = "edx";
                        break;
                    case "011": //3
                        rm32 = "ebx";
                        break;
                    case "100": //4
                        rm32 = "esp";
                        break;
                    case "101": //5
                        rm32 = "ebp";
                        break;
                    case "110": //6
                        rm32 = "esi";
                        break;
                    case "111": //7
                        rm32 = "edi";
                        break;
                }
                break;
        }

        //get the reg bit.
        switch (regBit) {
            case "000": //0
                reg = "eax";
                break;
            case "001": //1
                reg = "ecx";
                break;
            case "010": //2
                reg = "edx";
                break;
            case "011": //3
                reg = "ebx";
                break;
            case "100": //4
                reg = "esp";
                break;
            case "101": //5
                reg = "ebp";
                break;
            case "110": //6
                reg = "esi";
                break;
            case "111": //7
                reg = "edi";
                break;
            default:
                System.out.println("REG, N/A");
                break;
        }

        //Based on the MODR/M Byte
        //Translate the opcode  into 
        //the appropriate instruction
        if ((opcode == 0x81) && (regBit.equals("000"))) { //add r/m32, imm32

            b1 = get32BitNum();

            if (0x7fffffff >= b1) {
                immval += String.format("%02x", b1);
            } else {
                b1 = (b1 ^ 0xff) + 1;
                immval = "-0x" + String.format("%02x", b1);
            }

            bigEndianBytes = String.format("%08x", b1);

            immval += String.format("%08x", reverseByteOrder32(b1));

            disp += 5;
            ins = "add " + rm32 + "," + immval;
            instrVal = ins;

        } else if ((opcode == 0x83) && (regBit.equals("000"))) { //add r/m32, imm8

            b1 = getByte();

            if (0x7f >= b1) {
                immval += String.format("%02x", b1);
            } else {
                //take two's complement
                b1 = (b1 ^ 0xff) + 1;
                immval = "-0x" + String.format("%02x", b1);
            }

            bigEndianBytes = String.format("%02x", b1);

            ins = "add " + rm32 + "," + immval;

            disp += 3;
            instrVal = ins;
        } else if ((opcode == 0x81) && (regBit.equals("001"))) { //or r/m32, imm32

            b1 = get32BitNum();

            if (0x7fffffff >= b1) {
                immval += String.format("%08x", b1);
            } else {
                b1 = (b1 ^ 0xffffffff) + 1;
                immval = "-0x" + String.format("%08x", b1);
            }

            bigEndianBytes = String.format("%08x", b1);

            immval += String.format("%08x", reverseByteOrder32(b1));

            disp += 5;
            ins = "or " + rm32 + "," + immval;
            instrVal = ins;
        } else if ((opcode == 0x83) && (regBit.equals("001"))) { //or r/m32, imm8

            b1 = getByte();

            if (0x7f >= b1) {
                immval += String.format("%02x", b1);
            } else {
                //take two's complement
                b1 = (b1 ^ 0xff) + 1;
                immval = "-0x" + String.format("%02x", b1);
            }

            bigEndianBytes = String.format("%02x", b1);

            disp += 3;

            ins = "or " + rm32 + "," + immval;
            instrVal = ins;
        } else if ((opcode == 0x81) && (regBit.equals("100"))) { //and r/m32, imm32

            b1 = get32BitNum();

            if (0x7fffffff >= b1) {
                immval += String.format("%08x", b1);
            } else {
                b1 = (b1 ^ 0xffffffff) + 1;
                immval = "-0x" + String.format("%08x", b1);
            }

            bigEndianBytes = String.format("%08x", b1);

            immval += String.format("%08x", reverseByteOrder32(b1));

            disp += 5;
            ins = "and " + rm32 + "," + immval;
            instrVal = ins;

        } else if ((opcode == 0x83) && (regBit.equals("100"))) { //and r/m32, imm8

            b1 = getByte();

            if (0x7f >= b1) {
                immval += String.format("%02x", b1);
            } else {
                //take two's complement
                b1 = (b1 ^ 0xff) + 1;
                immval = "-0x" + String.format("%02x", b1);
            }

            bigEndianBytes = String.format("%02x", b1);

            disp += 3;
            ins = "and " + rm32 + "," + immval;
            instrVal = ins;
        } else if ((opcode == 0x81) && (regBit.equals("110"))) { //xor r/m32, imm32

            b1 = get32BitNum();

            if (0x7fffffff >= b1) {
                immval += String.format("%08x", b1);
            } else {
                b1 ^= 0xffffffff;
                immval = "-0x" + String.format("%08x", b1);
            }

            bigEndianBytes = String.format("%08x", b1);

            immval += String.format("%08x", reverseByteOrder32(b1));

            disp += 5;
            ins = "xor " + rm32 + "," + immval;
            instrVal = ins;

        } else if ((opcode == 0x83) && (regBit.equals("110"))) { //xor r/m32, imm8

            b1 = getByte();

            if (0x7f >= b1) {
                immval += String.format("%02x", b1);
            } else {
                //take two's complement
                b1 ^= 0xff;
                immval = "-0x" + String.format("%02x", b1);
            }

            bigEndianBytes = String.format("%02x", b1);

            disp += 3;
            ins = "xor " + rm32 + "," + immval;
            instrVal = ins;
        } else if ((opcode == 0x81) && (regBit.equals("111"))) { //cmp r/m32, imm32

            b1 = get32BitNum();

            if (0x7fffffff >= b1) {
                immval += String.format("%08x", b1);
            } else {

                b1 ^= 0xffffffff;
                immval = "-0x" + String.format("%08x", b1);
            }

            bigEndianBytes = String.format("%08x", b1);

            immval += String.format("%08x", reverseByteOrder32(b1));

            disp += 5;
            ins = "cmp " + rm32 + "," + immval;
            instrVal = ins;
        } else if ((opcode == 0x83) && (regBit.equals("111"))) { //cmp r/m32, imm8

            b1 = getByte();

            if (0x7f >= b1) {
                immval += String.format("%02x", b1);
            } else {
                //take two's complement
                b1 ^= (0xff + 1);
                immval = "-0x" + String.format("%02x", b1);
            }

            bigEndianBytes = String.format("%02x", b1);

            disp += 3;
            ins = "cmp " + rm32 + "," + immval;
            instrVal = ins;

        } else if ((opcode == 0xff) && (regBit.equals("010"))) { //call r/m32            

            ins = "call " + rm32;

            instrVal = ins;
            disp += 2;

        } else if ((opcode == 0xff) && (regBit.equals("001"))) { //dec r/m32

            ins = "dec " + rm32;
            disp += 2;
            instrVal = ins;
        } else if ((opcode == 0xff) && (regBit.equals("000"))) { //inc r/m32

            ins = "inc " + rm32;
            disp += 2;
            instrVal = ins;
        } else if ((opcode == 0xff) && (regBit.equals("100"))) { //jmp r/m32

            ins = "jmp " + rm32;

            disp += 2;
            instrVal = ins;

        } else if ((opcode == 0xff) && (regBit.equals("110"))) { //push r/m32

            ins = "push " + rm32;
            disp += 2;
            instrVal = ins;

        } else if ((opcode == 0xc1) && (regBit.equals("100"))) { //sal/shl r/m32, imm8

            b1 = getByte();
            bigEndianBytes = String.format("%02x", b1);

            immval += String.format("%02x", b1);

            ins = "shl " + rm32 + ", " + immval;
            //or sal...        

            disp += 3;
            instrVal = ins;

        } else if ((opcode == 0xd1) && (regBit.equals("100"))) { //sal/shl r/m32, 1

            ins = "sal " + rm32 + ", 1";

            //or shl...    
            disp += 2;
            instrVal = ins;

        } else if ((opcode == 0xc1) && (regBit.equals("101"))) { //shr r/m32, imm8

            b1 = getByte();
            bigEndianBytes = String.format("%02x", b1);

            immval += String.format("%02x", b1);
            disp += 3;
            ins = "shr " + rm32 + ", " + immval;

            instrVal = ins;

        } else if ((opcode == 0xd1) && (regBit.equals("101"))) { //shr r/m32, 1

            ins = "shr " + rm32 + ", 1";
            disp += 2;
            instrVal = ins;

        } else if ((opcode == 0xc1) && (regBit.equals("111"))) { //sar r/m32, imm8

            b1 = getByte();
            bigEndianBytes = String.format("%02x", b1);
            immval += String.format("%02x", b1);

            disp += 3;
            ins = "sar " + rm32 + ", " + immval;
            instrVal = ins;

        } else if ((opcode == 0xd1) && (regBit.equals("111"))) { //sar r/m32, 1

            ins = "sar " + rm32 + ", 1";
            disp += 2;
            instrVal = ins;

        } else if (opcode == 0x01) { //add r/m32,r32

            ins = "add " + rm32 + ", " + reg;
            disp += 2;
            instrVal = ins;

        } else if (opcode == 0x03) { //add r32,rm32

            ins = "add " + reg + ", " + rm32;
            disp += 2;
            instrVal = ins;

        } else if (opcode == 0x21) { //and r/m32, r32

            ins = "and " + rm32 + ", " + reg;
            disp += 2;
            instrVal = ins;
        } else if (opcode == 0x23) { //and r32, r/m32

            ins = "and " + reg + ", " + rm32;
            disp += 2;
            instrVal = ins;
        } else if (opcode == 0x39) { //cmp r/m32, r32

            ins = "cmp " + rm32 + ", " + reg;
            disp += 2;
            instrVal = ins;
        } else if (opcode == 0x3b) { //cmp r32, r/m32

            ins = "cmp " + reg + ", " + rm32;
            disp += 2;
            instrVal = ins;
        } else if (opcode == 0x8d) { //lea r32, [0x00000000]

            ins = "lea " + reg + "," + rm32;
            disp = 6;
            instrVal = ins;
        } else if (opcode == 0x89) { //mov r/m32,r32

            ins = "mov " + rm32 + ", " + reg;
            disp += 2;
            instrVal = ins;

        } else if (opcode == 0x8b) { //mov r32,r/m32

            ins = "mov " + reg + ", " + rm32;
            disp += 2;
            instrVal = ins;
        } else if (opcode == 0x0f1f) { //nop rm32 

            ins = "nop " + rm32 + ", " + reg;
            disp += 2;
            instrVal = ins;
        } else if (opcode == 0x09) { //or r/m32, r32 

            ins = "or " + rm32 + ", " + reg;
            disp += 2;
            instrVal = ins;
        } else if (opcode == 0x0b) { //or r32 , r/m32

            ins = "or " + reg + ", " + rm32;
            disp += 2;
            instrVal = ins;
        } else if (opcode == 0x8f) { //pop r/m32 , r32 

            ins = "pop " + rm32 + ", " + reg;
            disp += 2;
            instrVal = ins;
        } else if (opcode == 0xf30fb8) { //popcnt r32,rm32

            instrVal = "popcnt " + reg + "," + rm32;
            disp += 4;
        } else if (opcode == 0xf7) { //test r/m32,imm32 

            b1 = get32BitNum();

            b1 = reverseByteOrder32(b1);

            immval += String.format("%08x", b1);

            disp += 2;
            ins = "test " + rm32 + "," + immval;
            instrVal = ins;

            bigEndianBytes = String.format("%08x", reverseByteOrder32(b1));

        } else if (opcode == 0x85) { //test r/m32,r32

            ins = "test " + rm32 + ", " + reg;
            disp += 2;
            instrVal = ins;
        } else if (opcode == 0x31) { //xor rm32,r32

            ins = "xor " + rm32 + ", " + reg;
            disp += 2;
            instrVal = ins;

        } else if (opcode == 0x33) { //xor r32,rm32

            ins = "xor " + rm32 + ", " + reg;
            instrVal = ins;
            disp += 2;
        }
        return disp;

    }

    /*
     Utility functions for reading bytes and converting 16 and 32-bit ints.
     */
    private int getByte() {
        int b1 = 0;
        try {
            b1 = buff.read();

        } catch (IOException ex) {
            System.out.println("Error while reading file.\n" + ex);

        }

        return b1;
    }

    /*
     Assemble a 32 bit int 
     Shift each byte to the left by 8
     in order to properly
     build the 4 byte number.
     */
    private int get32BitNum() {

        int b1, b2, b3, b4;

        b4 = getByte();
        b4 <<= 24;
        b3 = getByte();
        b3 <<= 16;
        b2 = getByte();
        b2 <<= 8;
        b1 = getByte();

        b4 += b3;
        b4 += b2;
        b4 += b1;

        return b4;
    }

    //Make sure we can call and jump backwards.
    //For 32 bit loc.
    private int getOffset32(int b1, int disp) {

        immval = "";
        if (0x7fffffff > (count + disp + b1)) {
            b1 += (count + disp);
        } else {

            b1 += (count - 0xffffffff) + 1;
        }

        jmp_addr = b1;
        return b1;

    }

    //Make sure we can call and jump backwards.
    //For 8 bit location.
    private int getOffset(int b1, int disp) {

        immval = "";

        if (0x7f > (count + disp + b1)) {
            b1 += (count + disp);
        } else {

            b1 += (count - 0xff) + 1;
        }

        jmp_addr = b1;
        return b1;

    }

    //Endianess swapper function for 2 byte num
    private int reverseByteOrder16(int bval16) {

        int b1, b2;

        b1 = bval16 & 0xff;
        b2 = (bval16 >> 8) & 0xff;

        return (b1 << 8 | b2);
    }

    //Endianess swapper function for 4 byte num
    private int reverseByteOrder32(int bval32) {

        int b1 = (bval32) & 0xff;
        int b2 = (bval32 >> 8) & 0xff;
        int b3 = (bval32 >> 16) & 0xff;
        int b4 = (bval32 >> 24) & 0xff;

        return b1 << 24 | b2 << 16 | b3 << 8 | b4;

    }

    /*
     Binary file parsing logic.
     */
    public void parseBinary() {

        //get code size
        String value;
        int mod;
        //String operand2 = null;
        String[] operations;
        int disp = 0;
        boolean modrm = false;
        count = 0;

        try {

            buff = new BufferedInputStream(new FileInputStream(filename));

            while ((opcode = buff.read()) != -1) {

                if ((count == jmp_addr)) {

                    if (offsets.size() > 0) {
                        System.out.println(offsets.pop() + ":");
                    }
                }

                //handle possible nop r/m32,  jz rel32, jnz rel32
                if (opcode == 0x0f) {
                    opcode <<= 8;
                    int tmp = getByte();

                    opcode += tmp;
                    disp += 2;
                }
                //handle popcnt
                if (opcode == 0xf3) {

                    int b2, b3;
                    opcode <<= 16;
                    b2 = getByte();
                    b2 <<= 8;
                    opcode += b2;

                    b3 = getByte();

                    opcode += b3;
                }
                //get opcode from map
                value = opcodeMap.get(opcode);

                //if its not in the map, increase counter go to beginning of loop.
                if (value == null) {
                    System.out.println(String.format("%08x", count) + ":   "
                            + String.format("%02x", opcode) + "\t\t\t" + "Invalid Opcode");
                    count++;
                    continue;
                }

                //
                if (value.contains(":")) {
                    operations = value.split(":");
                    value = operations[0];
                }

                //check for a modr/m byte
                if (value.contains("mod")) {
                    modrm = true;
                }

                //if there is no modr/m byte
                if (!modrm) {
                    //determine if the value is 
                    //a simple inc,dec,pop, or push reg
                    if ((0x40 <= opcode) && (0x5F >= opcode)) {

                        disp = 0x01;

                        System.out.println(String.format("%08x", count) + ":   "
                                + String.format("%02x", opcode) + "\t\t\t" + value);
                    } //is this a nop/int3/ret?
                    else if ((opcode == 0x90) || (opcode == 0xcc) || (opcode == 0xc3)) {
                        disp = 0x01;
                        System.out.println(String.format("%08x", count) + ":   "
                                + String.format("%02x", opcode) + "\t\t\t" + value);
                    } //is this an add/and/cmp/or/test/xor?
                    else if ((opcode == 0x05) || (opcode == 0x25)
                            || (opcode == 0x3d) || (opcode == 0x35)
                            || (opcode == 0xA9) || (opcode == 0x0D)) {

                        addAndFriends = true;

                        //get displacement
                        disp = getDispForNonMod();

                        System.out.println(String.format("%08x", count) + ":   "
                                + String.format("%02x", opcode)
                                + bigEndianBytes + "\t\t" + value + immval);
                    } else {

                        disp = getDispForNonMod();

                        System.out.println(String.format("%08x", count) + ":   "
                                + String.format("%02x", opcode)
                                + bigEndianBytes + "\t\t" + value + " " + immval);
                    }

                } else {
                    //there is a mod r/m byte.
                    mod = getByte();
                    disp = getDispForModRMByte(mod);

                    if (opcode == 0x8d) {
                        System.out.println(String.format("%08x", count) + ":   "
                                + String.format("%02x", opcode) + String.format("%02x", mod)
                                + bigEndianBytes + "\t" + instrVal);
                    } else {
                        System.out.println(String.format("%08x", count) + ":   "
                                + String.format("%02x", opcode) + String.format("%02x", mod)
                                + bigEndianBytes + "\t\t" + instrVal);
                    }
                }
                //calculate displacement;
                count += disp;
                modrm = false;
            }

        } catch (IOException io) {

            System.err.println("Error while reading file: " + filename + ".\n" + io);
            System.err.println("Check the filename and try again.");
            System.err.println("Exiting...");

        } finally {
            if (buff != null) {
                try {
                    buff.close();
                } catch (IOException ex) {
                    System.err.println("Error while closing file: " + filename + ".\n" + ex);
                }
            }

        }
    }
}
