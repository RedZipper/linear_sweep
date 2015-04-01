/*
*

 @author Christina Ford
 @date 2/22/2015

 This file is part of the Simple Intel 32-bit Disassembler (SI 32D).

 SI 32D is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 SI 32D is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with SI 32D.  If not, see <http://www.gnu.org/licenses/>.

 *
 */
 
package disassembler;
 
public class Disassembler {

    /**
     * @param args the command line arguments
     * 
     */
    public static void main(String[] args) {

        if(args.length < 1) {      
            System.err.println("Usage: java -jar Disassembler.jar [filename]");
            return;
        } if (args.length > 1) {
            
            System.err.println("Usage: java -jar Disassembler.jar [filename]");
            return;
        }
         
        LinearSweep ndisasm = new LinearSweep(args[0]);
        
        ndisasm.parseBinary();      
    }
}
