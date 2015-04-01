/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package disassembler;

/**
 *
 * @author Christina Ford
 * 2/22/2015
 */
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
