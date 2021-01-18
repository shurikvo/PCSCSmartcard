import java.util.List;
import java.util.*;

public class PCSCSmartcardMain {
    private static final String sProject = "PCSCSmartcardMain";

    public static void main(String[] args) {
        int i, RC = 0, ReaderN;
        String sPart, sParam, sMKey, sSCP, sHChallenge = "2021222324252627", sCAnswer = "", sCmd, sResp;
        Scanner scanner;

        VLogger log = new VLogger();
        RC = log.init(sProject);
        if(RC < 0)
            return;
        log.writeMes(LogMesType.INFO, sProject+": Start");

        PcscShell pcl = new PcscShell(sProject);
        System.out.print("Coose reader: ");
        scanner = new Scanner(System. in);
        sCAnswer = scanner. nextLine();
        ReaderN = Integer.parseInt(sCAnswer);
        log.writeMes(LogMesType.INFO, "Reader: "+ReaderN);

        RC = pcl.connectCard(ReaderN);
        if(RC < 0)
            return;
        log.writeMes(LogMesType.INFO, "Connect: OK");

        sCmd = "00A4040008A000000003000000";
        sResp = pcl.sendAPDU(sCmd);

        sCmd = "80CA9F7F00";
        sResp = pcl.sendAPDU(sCmd);

        sCmd = "8050000008"+sHChallenge;
        sCAnswer = pcl.sendAPDU(sCmd);
        //----------------------------------------------------------------------------------------------------
        KeyChecker keyChecker = new KeyChecker(sProject);
        keyChecker.addMKey("00112233445566778899AABBCCDDEEFF");
        keyChecker.addMKey("404142434445464748494A4B4C4D4E4F");
        keyChecker.SCP = "02";

        RC = keyChecker.checkKey(sHChallenge, sCAnswer);
        if(RC < 0) {
            log.writeMes(LogMesType.ERROR, "Check Cryptogram: Failed");
            RC = pcl.disconnectCard();
            if(RC < 0)
                return;
            log.writeMes(LogMesType.INFO, "Disconnect: OK");
            return;
        }
        else {
            log.writeMes(LogMesType.INFO, "Check Cryptogram: OK "+keyChecker.getDiv());
            log.writeMes(LogMesType.INFO, "Key: "+keyChecker.CurKey+" Div: "+keyChecker.getDiv());
        }

        sCmd = keyChecker.MakeExtAuth(0);
        sResp = pcl.sendAPDU(sCmd);
        if(pcl.SW == 0x9000)
            log.writeMes(LogMesType.INFO, "Ext Auth: OK");
        else
            log.writeMes(LogMesType.INFO, "Ext Auth: ERROR");

        RC = pcl.disconnectCard();
        if(RC < 0)
            return;
        log.writeMes(LogMesType.INFO, "Disconnect: OK");
    }
}
